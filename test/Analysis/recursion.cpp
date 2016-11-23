// RUN: %clang_cc1 -analyze -analyzer-checker=alpha.core.RecursionChecker -verify %s

namespace obvious {

void simplestRecursiveFunction() {
    simplestRecursiveFunction(); // expected-warning {{Infinite recursion detected}}
}


void simplestMutuallyRecursiveFunction2();

void simplestMutuallyRecursiveFunction1() {
    simplestMutuallyRecursiveFunction2();
}

void simplestMutuallyRecursiveFunction2() {
    simplestMutuallyRecursiveFunction1(); // expected-warning {{Infinite recursion detected}}
}

void startMutualRecursionTest() {
    simplestMutuallyRecursiveFunction1();
}

}

namespace region_changes {

// some global variable
int SampleGlobalVariable = 0;

void firstInNoWarnCycle();
void secondInNoWarnCycle();
void thirdInNoWarnCycle();

void firstInNoWarnCycle() {
    secondInNoWarnCycle();
}

// we spoil the frame here by touching global variable - no warnings
void secondInNoWarnCycle() {
    if (++SampleGlobalVariable)
        thirdInNoWarnCycle();
}

// no warning because frame of f1 has been spoiled in f2!
void thirdInNoWarnCycle() {
    firstInNoWarnCycle();
}

void startNoWarnCycle() {
    firstInNoWarnCycle();
}


void firstInWarnCycle();
void secondInWarnCycle();
void thirdInWarnCycle();
void fourthInWarnCycle();

void secondInWarnCycle() {
    thirdInWarnCycle();
}

void thirdInWarnCycle() {
    fourthInWarnCycle();
}

void fourthInWarnCycle() {
   secondInWarnCycle(); // expected-warning {{Infinite recursion detected}}
}

// only the first frame is spoiled, the two over it are fine
void firstInWarnCycle() {
    SampleGlobalVariable = 1;
    if (SampleGlobalVariable++ < 5)
        secondInWarnCycle();
}

}

namespace obvious_with_arguments {

void oneClassArgFunction(int a) {
  oneClassArgFunction(a); // expected-warning {{Infinite recursion detected}}
}

void twoArgsSecondMutuallyRecursiveFunction(int a, int b);

void twoArgsMutuallyRecursiveFunction(int a, int b) {
  twoArgsSecondMutuallyRecursiveFunction(b, a);
}

void twoArgsSecondMutuallyRecursiveFunction(int a, int b) {
  twoArgsMutuallyRecursiveFunction(b, a); // expected-warning {{Infinite recursion detected}}
}

void startMutuallyRecursiveCycle() {
    twoArgsMutuallyRecursiveFunction(1, 2);
}


// Making sure the number of parameters doesn't cause problems for the checker
void oneArgFunction(int a);

void twoArgsFunction(int a, int b) {
  oneArgFunction(a);
}

void oneArgFunction(int a) {
  twoArgsFunction(a, 3); // expected-warning {{Infinite recursion detected}}
}

void startVariableClassArgNumberCycle() {
    oneArgFunction(1);
}


bool onlyForwardDecl();

// we don't know anything about onlyForwardDecl so the RegionChanges callbacks
// ensure we don't rely on it to decide if the recursive call will happen
void recursiveFunctionUsingForwardDecl() {
  if (!onlyForwardDecl())
    recursiveFunctionUsingForwardDecl();
}

}

namespace object_oriented {

struct ClassA {
  void selfRecursiveMethod() {
    selfRecursiveMethod(); // expected-warning {{Infinite recursion detected}}
  }

  // Mutual recursion - simplest case
  void mutuallyRecursiveMethod() {
      anotherMutuallyRecursiveMethod();
  }

  void anotherMutuallyRecursiveMethod() {
      mutuallyRecursiveMethod(); // expected-warning {{Infinite recursion detected}}
  }
  void methodWithArg(int a) {
    methodWithArg(a); // expected-warning {{Infinite recursion detected}}
  }

  void twoArgsMutuallyRecursive(int a, int b) {
    anotherTwoArgsMutuallyRecursive(b, a);
  }

  void anotherTwoArgsMutuallyRecursive(int a, int b) {
    twoArgsMutuallyRecursive(b, a); // expected-warning {{Infinite recursion detected}}
  }

  // different number arguments in mutually recursive methods
  void twoArgsCallingOneArgsMethod(int a, int b) {
    oneArgMethodCallingTwoArgsMethod(a);
  }

  void oneArgMethodCallingTwoArgsMethod(int a) {
    twoArgsCallingOneArgsMethod(a, 3); // expected-warning {{Infinite recursion detected}}
  }

};

void startSelfRecursiveMethod() {
  ClassA a;
  a.selfRecursiveMethod();
}

void startMutuallyRecursiveMethodCycle() {
  ClassA a;
  a.mutuallyRecursiveMethod();
}

void startMethodWithArg() {
  ClassA a;
  a.methodWithArg(1);
}

void startTwoArgsMutuallyRecursiveCycle() {
  ClassA a;
  a.twoArgsMutuallyRecursive(1, 2);
}

void start() {
  ClassA a;
  a.twoArgsCallingOneArgsMethod(1, 3);
}

class ClassB {
public:

  int methodTakingObjectParam(ClassA& a) {
    return methodTakingObjectParam(a); // expected-warning {{Infinite recursion detected}}
  }


  ClassA multiArgObjectTakingMutuallyRecursive(ClassA& a, int b) {
    return anotherMultiArgObjectTakingMutuallyRecursive(b, a);
  }

  ClassA anotherMultiArgObjectTakingMutuallyRecursive(int a, ClassA& b) {
    return multiArgObjectTakingMutuallyRecursive(b, a); // expected-warning {{Infinite recursion detected}}
  }


  int recursiveWithDifferentThisPointer(const ClassB& b) const {
    return b.recursiveWithDifferentThisPointer(*this); // expected-warning {{Infinite recursion detected}}
  }


  void mutuallyRecursiveWithDifferentThisPointer(const ClassB& b) const {
    b.anotherMutuallyRecursiveWithDifferentThisPointer(*this);
  }

  void anotherMutuallyRecursiveWithDifferentThisPointer(const ClassB& b) const {
    b.mutuallyRecursiveWithDifferentThisPointer(*this); // expected-warning {{Infinite recursion detected}}
  }

};

void startMethodTakingObjectParam() {
  ClassB b;
  ClassA a;
  b.methodTakingObjectParam(a);
}

void startMultiArgObjectTakingMutuallyRecursive() {
  ClassB b;
  ClassA a;
  b.multiArgObjectTakingMutuallyRecursive(a, 3);
}

void startRecursiveWithDifferentThisPointer() {
  ClassB b1, b2;
  b1.recursiveWithDifferentThisPointer(b2);
}

void startMutuallyRecursiveWithDifferentThisPointer() {
  ClassB b1, b2;
  b1.mutuallyRecursiveWithDifferentThisPointer(b2);
}

}
