module foo;

global h = 0;
global i = h;
#          ^defined: 3
       h;
#      ^defined: 3
global j = foo::h;
#          ^defined:
global k = l;
#          ^defined:
