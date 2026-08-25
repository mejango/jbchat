# Lessons

- Never `cat >` a tracked file (tasks/todo.md) without looking first — it had 362 lines of prior plans. Append, or restore from HEAD and append.
- Lab fixtures diverge from provisioned projects (policy_revision 12, foreign realm_id): anything that re-derives authority rows must read kind/revision/realm from the rows it is rewriting, never from literals.
