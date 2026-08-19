"use client";

import { useEffect } from "react";

/**
 * A `default` Trusted Types policy so the wallet sign-in SDKs work under
 * `require-trusted-types-for 'script'`. Para (its MPC worker) and
 * WalletConnect assign script URLs without registering their own policy;
 * the browser routes those assignments through the `default` policy. We
 * pass a URL through only when it points at a known wallet-SDK host and
 * throw otherwise, so the strict protection still holds for every other
 * script URL on the page.
 */

const ALLOWED_SCRIPT_HOSTS = [
  "app.getpara.com",
  "api.getpara.com",
  "app.usecapsule.com",
  "api.usecapsule.com",
];

function isAllowedScriptUrl(value: string): boolean {
  try {
    const url = new URL(value, window.location.origin);
    if (url.origin === window.location.origin) return true;
    return (
      url.protocol === "https:" &&
      ALLOWED_SCRIPT_HOSTS.some(
        (host) => url.hostname === host || url.hostname.endsWith(`.${host}`),
      )
    );
  } catch {
    return false;
  }
}

interface TrustedTypesWindow {
  readonly trustedTypes?: {
    createPolicy(
      name: string,
      rules: {
        createScriptURL?: (value: string) => string;
        createHTML?: (value: string) => string;
        createScript?: (value: string) => string;
      },
    ): unknown;
  };
}

let installed = false;

export function TrustedTypesPolicy() {
  useEffect(() => {
    if (installed) return;
    installed = true;
    const factory = (window as unknown as TrustedTypesWindow).trustedTypes;
    if (!factory) return;
    try {
      factory.createPolicy("default", {
        createScriptURL(value) {
          if (!isAllowedScriptUrl(value)) {
            throw new TypeError(`Blocked script URL: ${value}`);
          }
          return value;
        },
        // The default policy vouches for wallet-SDK script URLs only.
        // HTML and script-body sinks stay rejected: WalletConnect's own
        // templating uses its named lit-html/wcm policies, and nothing
        // first-party assigns raw HTML or script strings.
        createHTML(value) {
          throw new TypeError(`Blocked HTML sink: ${value.slice(0, 32)}`);
        },
        createScript(value) {
          throw new TypeError(`Blocked inline script: ${value.slice(0, 32)}`);
        },
      });
    } catch {
      // A default policy already exists (e.g. StrictMode double-invoke) -
      // the first one stands.
    }
  }, []);
  return null;
}
