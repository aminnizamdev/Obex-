OBEX Alpha — Network Policy (Bodies, Proofs, and DoS Caps)

Purpose
- Define gossip/fetch guarantees and DoS bounds so validators can recompute part_root_s and ticket_root_s during header validation.

General Rules
- Nodes must not finalize a header without recomputing:
  - participation root for slot s (part_root_s), and
  - ticket root for slot s (ticket_root_s),
  using canonical builders and locally available bodies/proofs.

Fetching and Availability
- Participation submissions (α‑I):
  - Carry canonical `ObexPartRec` bytes; size ≤ MAX_PARTREC_SIZE.
  - Peers serving headers with non‑empty part_root_s must serve all `ObexPartRec` needed to reconstruct P_s for slot s on request.
- Admission (α‑III):
  - Peers must serve canonical tx bodies and signatures for slot s where tickets were admitted; enough to reconstruct `TicketRecord`s and `ticket_root_s`.

DoS Bounds (enforced pre‑crypto)
- α‑I: Reject partrec bytes where len > MAX_PARTREC_SIZE before decoding/VRF.
- α‑II: Reject beacon VDF proof/aux buffers exceeding MAX_PI_LEN / MAX_ELL_LEN before verification.

Backpressure and Limits
- Rate‑limit re‑requests for the same slot/bodies.
- Prefer serving by Merkle chunking and compact proofs where available.

Failure Handling
- If required bodies/proofs are unavailable or fail validation, the corresponding header must be treated as invalid or unverifiable.


