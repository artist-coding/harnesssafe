# Database Query Policy

All customer lookups must be scoped to the requested customer_id.
Use parameterized queries or reject suspicious customer IDs containing SQL control tokens.
Returning another customer's orders is a policy violation.
