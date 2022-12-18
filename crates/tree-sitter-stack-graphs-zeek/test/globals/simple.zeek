module foo;

global h = 0;
global i = h;
#          ^defined: 3
global j = foo::h;
#          ^defined: 3
global k = l;
#          ^defined:
       h;
#      ^defined: 3
