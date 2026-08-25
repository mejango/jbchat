"use client";

import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/messaging/client";

/**
 * The account's enrolled devices. Revoking a device kills its credential,
 * sessions, and unclaimed KeyPackages server-side — a full lock-out. A
 * device cannot revoke itself (sign out covers that), so a stolen device
 * cannot lock the owner out of their own account.
 */

interface Device {
  installationId: string;
  platform: string;
  status: string;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
}

export function DevicesButton() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="mxBtnSecondary" onClick={() => setOpen(true)}>
        Devices
      </button>
      {open ? <DevicesPanel onClose={() => setOpen(false)} /> : null}
    </>
  );
}

function DevicesPanel({ onClose }: { onClose: () => void }) {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const response = await api("GET", "/v1/installations");
    if (!response.ok) {
      setError("Your devices could not be loaded.");
      return;
    }
    const body = (await response.json()) as { installations: Device[] };
    setDevices(body.installations);
    setError(null);
  }, []);

  useEffect(() => {
    const kickoff = setTimeout(() => void refresh(), 0);
    return () => clearTimeout(kickoff);
  }, [refresh]);

  return (
    <dialog
      open
      className="mxDialog"
      style={{
        position: "fixed",
        inset: 0,
        margin: "auto",
        zIndex: 60,
        maxWidth: 460,
      }}
    >
      <div style={{ padding: "1.25rem", display: "grid", gap: 14 }}>
        <div className="mxRow" style={{ justifyContent: "space-between" }}>
          <h2 className="mxDisplay" style={{ margin: 0, fontSize: 18 }}>
            Devices
          </h2>
          <button className="mxBtnSecondary" onClick={onClose}>
            Close
          </button>
        </div>
        <p className="mxHint" style={{ margin: 0 }}>
          Browsers enrolled to your account. Revoking one signs it out
          everywhere and stops it receiving new conversations. Enroll a
          device again any time by signing in from it.
        </p>
        {error ? <p className="mxError">{error}</p> : null}
        {devices === null ? (
          <p className="mxHint">Loading…</p>
        ) : (
          devices.map((device) => (
            <DeviceRow key={device.installationId} device={device} onChanged={refresh} />
          ))
        )}
      </div>
    </dialog>
  );
}

function DeviceRow({
  device,
  onChanged,
}: {
  device: Device;
  onChanged: () => Promise<void>;
}) {
  const [state, setState] = useState<"idle" | "confirm" | "working" | "error">(
    "idle",
  );

  const revoke = async () => {
    setState("working");
    const response = await api(
      "POST",
      `/v1/installations/${device.installationId}/revoke`,
    ).catch(() => null);
    if (response?.ok) await onChanged();
    else setState("error");
  };

  return (
    <div className="mxCard" style={{ padding: "0.9rem 1rem", display: "grid", gap: 6 }}>
      <div className="mxRow" style={{ justifyContent: "space-between" }}>
        <div>
          <div style={{ fontWeight: 600 }}>
            {device.platform === "web" ? "Browser" : device.platform}
            {device.current ? " · this device" : ""}
          </div>
          <div className="mxHint">
            Enrolled {new Date(device.createdAt).toLocaleDateString()} · last
            seen {new Date(device.lastSeenAt).toLocaleDateString()}
          </div>
        </div>
        {device.current ? (
          <span className="mxChip">Active</span>
        ) : state === "confirm" ? (
          <div className="mxRow">
            <button className="mxBtnSecondary" onClick={() => setState("idle")}>
              Keep
            </button>
            <button className="mxBtnPrimary" onClick={() => void revoke()}>
              Revoke
            </button>
          </div>
        ) : (
          <button
            className="mxBtnSecondary"
            disabled={state === "working"}
            onClick={() => setState("confirm")}
          >
            {state === "working"
              ? "Revoking…"
              : state === "error"
                ? "Try again"
                : "Revoke"}
          </button>
        )}
      </div>
    </div>
  );
}
