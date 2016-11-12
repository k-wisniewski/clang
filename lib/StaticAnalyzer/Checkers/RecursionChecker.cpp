// InfiniteRecursionChecker.cpp - Test if function is infinitely
// recursive--*--//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This defines TestAfterDivZeroChecker, a builtin check that performs checks
//  for division by zero where the division occurs before comparison with zero.
//
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

REGISTER_SET_WITH_PROGRAMSTATE(DirtyStackFrames, const clang::StackFrameContext *)

namespace {
using namespace clang;
using namespace ento;

class RecursionChecker
    : public Checker<check::PreCall, check::RegionChanges, check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

  void emitReport(CheckerContext &C) const;

  bool compareArgs(CheckerContext &C, const ProgramStateRef &State,
                   const SVal &CurArg, const SVal &PrevArg) const;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  bool wantsRegionChangeUpdate(ProgramStateRef State,
                               const LocationContext *LCtx) const;

  ProgramStateRef
  checkRegionChanges(ProgramStateRef State,
                     const InvalidatedSymbols *Invalidated,
                     ArrayRef<const MemRegion *> ExplicitRegions,
                     ArrayRef<const MemRegion *> Regions, const CallEvent *Call,
                     const LocationContext *LCtx) const;
  void checkPostCall(const CallEvent &Call,
                                       CheckerContext &C) const;
};
}


void RecursionChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {

  const FunctionDecl *CurFuncDecl =
      dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!CurFuncDecl)
    return;
  CurFuncDecl = CurFuncDecl->getCanonicalDecl();

  const ProgramStateRef State = C.getState();

  for (const auto *ParentLC = C.getStackFrame()->getParent();
       ParentLC != nullptr; ParentLC = ParentLC->getParent()) {

    if (ParentLC->getKind() != LocationContext::StackFrame)
      continue;


    const StackFrameContext *PrevStackFrameCtx =
        ParentLC->getCurrentStackFrame();

    if (State->contains<DirtyStackFrames>(PrevStackFrameCtx))
      return;

    const FunctionDecl *PrevFuncDecl =
        (const FunctionDecl *)PrevStackFrameCtx->getDecl();
    PrevFuncDecl = PrevFuncDecl->getCanonicalDecl();

    if (PrevFuncDecl != CurFuncDecl)
      continue;

    bool SameArgs = true;
    for (unsigned i = 0; SameArgs && i < CurFuncDecl->getNumParams(); ++i) {
      SVal CurArg = Call.getArgSVal(i);
      SVal PrevArg = State->getArgSVal(PrevStackFrameCtx, i);
      SameArgs = SameArgs && compareArgs(C, State, CurArg, PrevArg);
    }

    if (SameArgs)
      emitReport(C);
  }
}
void RecursionChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State->remove<DirtyStackFrames>(C.getStackFrame());
}
bool RecursionChecker::compareArgs(CheckerContext &C,
                                   const ProgramStateRef &state,
                                   const SVal &curArg,
                                   const SVal &prevArg) const {
  SValBuilder &sValBuilder = C.getSValBuilder();
  ConstraintManager &constraintManager = C.getConstraintManager();

  SVal argsEqualSVal = sValBuilder.evalBinOp(state, BO_EQ, curArg, prevArg,
                                             sValBuilder.getConditionType());
  Optional<DefinedSVal> argsEqual = argsEqualSVal.getAs<DefinedSVal>();

  if (!argsEqual)
    return false;

  ProgramStateRef stateEQ, stateNEQ;
  std::tie(stateEQ, stateNEQ) = constraintManager.assumeDual(state, *argsEqual);

  if (stateNEQ)
    return false;

  return true;
}

bool RecursionChecker::wantsRegionChangeUpdate(
    ProgramStateRef State, const LocationContext *LCtx) const {
  return true;
}

ProgramStateRef RecursionChecker::checkRegionChanges(
    ProgramStateRef State, const InvalidatedSymbols *Invalidated,
    ArrayRef<const MemRegion *> ExplicitRegions,
    ArrayRef<const MemRegion *> Regions, const CallEvent *Call,
    const LocationContext *LCtx) const {
  State = State->add<DirtyStackFrames>(LCtx->getCurrentStackFrame());
  for (const auto *ParentLC = LCtx->getCurrentStackFrame()->getParent();
       ParentLC != nullptr; ParentLC = ParentLC->getParent()) {
    State = State->add<DirtyStackFrames>(ParentLC->getCurrentStackFrame());
  }
  return State;
}

void RecursionChecker::emitReport(CheckerContext &C) const {
  if (!BT)
    BT.reset(
        new BugType(this, "Infinite recursion detected", "RecursionChecker"));

  ExplodedNode *node = C.generateErrorNode();
  if (!node)
    return;

  auto report = llvm::make_unique<BugReport>(*BT, BT->getName(), node);
  C.emitReport(std::move(report));
}

void ento::registerRecursionChecker(CheckerManager &mgr) {
  mgr.registerChecker<RecursionChecker>();
}
