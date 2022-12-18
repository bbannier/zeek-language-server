# --- path: a.zeek ---
module A;
global x = 0;
  y;
# ^defined:
# --- path: b.zeek ---
module B;
global y = 1;
  x;
# ^defined:
  A::x;
# ^defined: 3
  B::x;
# ^defined:
  B::y;
# ^defined: 8
