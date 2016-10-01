//InfiniteRecursionChecker.cpp - Test if function is infinitely recursive--*--//
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

using namespace clang;
using namespace ento;

namespace {
class DirtyStackFrameState {

};

class RecursionChecker : public Checker<check::PreCall,
                                        check::RegionChanges> {
  mutable std::unique_ptr<BugType> BT;

  void emitReport(CheckerContext &C) const;

  bool compareArgs(CheckerContext &C,
                   const ProgramStateRef &State,
                   const SVal &CurArg,
                   const SVal &PrevArg) const;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  bool wantsRegionChangeUpdate(ProgramStateRef State,
                               const LocationContext *LCtx) const;

  ProgramStateRef checkRegionChanges(ProgramStateRef State,
                                     const InvalidatedSymbols *Invalidated,
                                     ArrayRef<const MemRegion *> ExplicitRegions,
                                     ArrayRef<const MemRegion *> Regions,
                                     const CallEvent *Call,
                                     const LocationContext *LCtx) const;
};
}

void RecursionChecker::checkPreCall(const CallEvent &Call,
                                            CheckerContext &C) const {

  const FunctionDecl
      *CurFuncDecl = (const FunctionDecl *) C.getStackFrame()->getDecl();
  CurFuncDecl = CurFuncDecl->getCanonicalDecl();

  const ProgramStateRef State = C.getState();

  for (const auto *ParentLC = C.getStackFrame()->getParent();
       ParentLC != nullptr; ParentLC = ParentLC->getParent()) {
    if (ParentLC->getKind() != LocationContext::StackFrame)
      continue;

    const StackFrameContext
        *PrevStackFrameCtx = ParentLC->getCurrentStackFrame();
    const FunctionDecl
        *PrevFuncDecl = (const FunctionDecl *) PrevStackFrameCtx->getDecl();
    PrevFuncDecl = PrevFuncDecl->getCanonicalDecl();

    if (PrevFuncDecl != CurFuncDecl)
      continue;

    bool SameArguments = true;
    for (unsigned i = 0; SameArguments && i < CurFuncDecl->getNumParams();
         ++i) {
      SVal CurArg = Call.getArgSVal(i);
      SVal PrevArg = State->getArgSVal(PrevStackFrameCtx, i);
      SameArguments = SameArguments && compareArgs(C, State, CurArg, PrevArg);
    }

    if (SameArguments)
      emitReport(C);
  }
}

bool RecursionChecker::compareArgs(CheckerContext &C,
                                           const ProgramStateRef &state,
                                           const SVal &curArg,
                                           const SVal &prevArg) const {
  SValBuilder &sValBuilder = C.getSValBuilder();
  ConstraintManager &constraintManager = C.getConstraintManager();

  SVal argsEqualSVal = sValBuilder.evalBinOp(state,
                                             BO_EQ,
                                             curArg,
                                             prevArg,
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

bool
RecursionChecker::wantsRegionChangeUpdate(ProgramStateRef State,
                                          const LocationContext *LCtx) const {
  return false;
}

ProgramStateRef
RecursionChecker::checkRegionChanges(ProgramStateRef State,
                                     const InvalidatedSymbols *Invalidated,
                                     ArrayRef<const MemRegion *> ExplicitRegions,
                                     ArrayRef<const MemRegion *> Regions,
                                     const CallEvent *Call,
                                     const LocationContext *LCtx) const {
  return State;
}

void RecursionChecker::emitReport(CheckerContext &C) const {
  if (!BT)
    BT.reset(new BugType(this,
                         "Infinite recursion detected",
                         "RecursionChecker"));

  ExplodedNode *node = C.generateErrorNode();
  if (!node)
    return;

  auto report = llvm::make_unique<BugReport>(*BT, BT->getName(), node);
  C.emitReport(std::move(report));
}

void ento::registerRecursionChecker(CheckerManager &mgr) {
  mgr.registerChecker<RecursionChecker>();
}

