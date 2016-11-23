// RecursionChecker.cpp - Tests for infinitely recursive functions -*- C++ -*-//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This defines a checker that aims to find cases of infinite recursion
// by searching up the call stack. It is in alpha.core but will hopefully
// eventually move to core package.
//
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

// Stackframe is considered "dirty", when there was any kind of region change
// in it or in any function that was called from it.
// As you see below, the checker then stops the search down the stack once
// it encounters such a "dirty" frame. The reason for such behavior is that
// we can no longer be sure that conditions upon which the recursive call
// depends on did not change in an unpredictable way. The class of region changes
// that trigger this behavior will be more fine-grained in subsequent versions of
// this patch.
REGISTER_SET_WITH_PROGRAMSTATE(DirtyStackFrames,
                               const clang::StackFrameContext *)

namespace {
using namespace clang;
using namespace ento;

class RecursionChecker : public Checker<check::PreCall,
                                        check::PreObjCMessage,
                                        check::RegionChanges,
                                        check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

  void emitReport(CheckerContext &C) const;

  Optional<SVal> getThisArgument(const CallEvent &Call) const;

  bool compareArgs(const SVal &curArg,
                   const SVal &prevArg,
                   CheckerContext &C) const;

  bool checkReceiversSame(const CallEvent &Call,
                          const StackFrameContext *SFC,
                          CheckerContext &C) const;

  bool checkThisPointersSame(const CallEvent &Call,
                             const StackFrameContext *SFC,
                             CheckerContext &C) const;

  bool checkAllArgumentsSame(const CallEvent &Call,
                             const StackFrameContext *SFC,
                             CheckerContext &C) const;

  void checkPreCallImpl(const CallEvent &Call, CheckerContext &C) const;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    checkPreCallImpl(Call, C);
  }

  void checkPreObjCMessage(const ObjCMethodCall &Msg, CheckerContext &C) const {
    checkPreCallImpl(Msg, C);
  }

  ProgramStateRef checkRegionChanges(ProgramStateRef State,
                                     const InvalidatedSymbols *Invalidated,
                                     ArrayRef<const MemRegion *> ExplicitRegions,
                                     ArrayRef<const MemRegion *> Regions,
                                     const LocationContext *LCtx,
                                     const CallEvent *Call) const;

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};
}

ProgramStateRef RecursionChecker::checkRegionChanges(
    ProgramStateRef State, const InvalidatedSymbols *Invalidated,
    ArrayRef<const MemRegion *> ExplicitRegions,
    ArrayRef<const MemRegion *> Regions,
    const LocationContext *LCtx,
    const CallEvent *Call) const {

  for (const auto *SFC = LCtx->getCurrentStackFrame();
       SFC != nullptr;
       SFC = SFC->getParent()->getCurrentStackFrame())
    State = State->add<DirtyStackFrames>(SFC);

  return State;
}

void RecursionChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State->remove<DirtyStackFrames>(C.getStackFrame());
}

void RecursionChecker::checkPreCallImpl(const CallEvent &Call,
                                        CheckerContext &C) const {

  for (const auto *SFC = C.getStackFrame();
       SFC != nullptr;
       SFC = SFC->getParent()->getCurrentStackFrame()) {
    if (C.getState()->contains<DirtyStackFrames>(SFC))
      return;

    if (Call.getDecl() != SFC->getDecl())
      continue;

    if (isa<ObjCMethodCall>(Call) && !checkReceiversSame(Call, SFC, C))
      continue;
    else if (!checkThisPointersSame(Call, SFC, C))
      continue;

    if (checkAllArgumentsSame(Call, SFC, C))
      emitReport(C);
  }
}

inline bool
RecursionChecker::checkAllArgumentsSame(const CallEvent &Call,
                                        const StackFrameContext *SFC,
                                        CheckerContext &C) const {
  bool SameArgs = true;
  for (unsigned i = 0; SameArgs && i < Call.getNumArgs(); ++i) {
    SVal CurArg = Call.getArgSVal(i);
    SVal PrevArg = C.getState()->getArgSVal(SFC, i);
    SameArgs = SameArgs && compareArgs(CurArg, PrevArg, C);
  }
  return SameArgs;
}

inline bool
RecursionChecker::checkThisPointersSame(const CallEvent &Call,
                                        const StackFrameContext *SFC,
                                        CheckerContext &C) const {
  const Optional<SVal> CurThis = getThisArgument(Call);
  const Optional<SVal> PrevThis = C.getState()->getThisSVal(SFC);

  return !CurThis || compareArgs(*CurThis, *PrevThis, C);
}

inline bool
RecursionChecker::checkReceiversSame(const CallEvent &Call,
                                     const StackFrameContext *SFC,
                                     CheckerContext &C) const {
  const ObjCMethodCall *Msg_ = dyn_cast<const ObjCMethodCall>(&Call);

  const SVal CurReceiver = Msg_->getReceiverSVal();
  const Optional<SVal> PrevReceiver =
      C.getState()->getObjCMessageReceiverSVal(SFC);

  return PrevReceiver && *PrevReceiver == CurReceiver;
}

inline void
RecursionChecker::emitReport(CheckerContext &C) const {
  if (!BT)
    BT.reset(new BugType(this,
                         "Infinite recursion detected",
                         categories::LogicError));

  ExplodedNode *node = C.generateErrorNode();
  if (!node)
    return;

  auto report = llvm::make_unique<BugReport>(*BT, BT->getName(), node);
  C.emitReport(std::move(report));
}

inline Optional<SVal>
RecursionChecker::getThisArgument(const CallEvent &Call) const {
  const FunctionDecl *F = dyn_cast<FunctionDecl>(Call.getDecl());
  if (!F)
    return None;
  F = F->getCanonicalDecl();

  Optional<SVal> CurThis;
  if (isa<CXXMethodDecl>(F))
    CurThis = cast<CXXInstanceCall>(&Call)->getCXXThisVal();
  else if (isa<CXXConstructorDecl>(F))
    CurThis = cast<CXXConstructorCall>(&Call)->getCXXThisVal();
  else if (isa<CXXDestructorDecl>(F))
    CurThis = cast<CXXDestructorCall>(&Call)->getCXXThisVal();

  return CurThis;
}

inline bool
RecursionChecker::compareArgs(const SVal &curArg,
                              const SVal &prevArg,
                              CheckerContext &C) const {
  const ProgramStateRef state = C.getState();
  SValBuilder &sValBuilder = C.getSValBuilder();
  ConstraintManager &constraintManager = C.getConstraintManager();

  SVal argsEqualSVal = sValBuilder.evalBinOp(state, BO_EQ, curArg, prevArg,
                                             sValBuilder.getConditionType());
  Optional<DefinedSVal> argsEqual = argsEqualSVal.getAs<DefinedSVal>();

  if (!argsEqual)
    return false;

  ProgramStateRef stateEQ, stateNEQ;
  std::tie(stateEQ, stateNEQ) = constraintManager.assumeDual(state, *argsEqual);

  return !stateNEQ;
}

void ento::registerRecursionChecker(CheckerManager &mgr) {
  mgr.registerChecker<RecursionChecker>();
}
