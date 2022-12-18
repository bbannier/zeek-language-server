# --- path: a.zeek ---
module foo;
global a = 1;
# --- path: b.zeek ---
module foo;
global b = 1;
       a;
#      ^defined: 3
  foo::a;
#      ^defined: 3
  foo::b;
#      ^defined: 6
