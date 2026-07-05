# idor verification checklist (fixture)

- Excludes program-documented exclusion classes.
- Distinguishes a real bug from public-by-design endpoints: the reached object
  must hold data private to another user/tenant.
- Requires a non-trivial impact gate: demonstrated cross-tenant data, not a bare
  200-vs-403 status difference.
