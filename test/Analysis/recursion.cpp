// RUN: %clang_cc1 -analyze -analyzer-checker=alpha.core.RecursionChecker -verify %s

namespace obvious {

void f() {
    f(); // expected-warning {{Infinite recursion detected}}
}

void h();

// Mutual recursion - simplest case
void g() {
    h(); // expected-warning {{Infinite recursion detected}}
}

void h() {
    g();
}

}

namespace global_touching {

// some global variable
int SampleGlobalVariable = 0;

void f2();
void f3();
void f1();

void f1() {
    f2();
}

// we spoil the frame here by touching global variable - no warnings
void f2() {
    SampleGlobalVariable = 1;
    f3();
}

// no warning because frame of f1 has been spoiled in f2!
void f3() {
    f1();
}

void f() {
    f1();
}


void f5();
void f6();
void f7();
void f4();

void f5() {
    f6();
}

void f6() {
    f7();
}

void f7() {
   f5(); // expected-warning {{Infinite recursion detected}}
}

// only the first frame is spoiled, the two over it are fine
void f4() {
    SampleGlobalVariable = 1;
    f5();
}

}
