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
class InfiniteRecursionChecker : public Checker<check::PreCall, check::RegionChanges> {
  mutable std::unique_ptr<BugType> BT;

  void emitReport(CheckerContext &C) const;

  Optional<SVal> getStackFrameArg(const ProgramStateRef &state,
                                  const StackFrameContext *stackFrameCtx,
                                  unsigned int argIdx) const;

  ArrayRef<SVal> getStackFrameArgs(const ProgramStateRef &state, const StackFrameContext *stackFrameCtx) const;

  bool compareArgs(CheckerContext &C, const ProgramStateRef &state, const SVal &curArg, const SVal &prevArg) const;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  bool wantsRegionChangeUpdate(ProgramStateRef State, const LocationContext *LCtx) const;

  ProgramStateRef checkRegionChanges(ProgramStateRef State,
                                     const InvalidatedSymbols *Invalidated,
                                     ArrayRef<const MemRegion *> ExplicitRegions,
                                     ArrayRef<const MemRegion *> Regions,
                                     const CallEvent *Call,
                                     const LocationContext *LCtx) const;
};
}

void InfiniteRecursionChecker::checkPreCall(const CallEvent &Call,
                                            CheckerContext &C) const {

  const FunctionDecl *CurFuncDecl = (const FunctionDecl *) C.getStackFrame()->getDecl();
  CurFuncDecl = CurFuncDecl->getCanonicalDecl();

  const ProgramStateRef state = C.getState();


  for (const auto *parentLC = C.getStackFrame()->getParent(); parentLC != nullptr; parentLC = parentLC->getParent()) {
    if (parentLC->getKind() != LocationContext::StackFrame)
      continue;

    const StackFrameContext *prevStackFrameCtx = parentLC->getCurrentStackFrame();
    const FunctionDecl *prevFuncDecl = (const FunctionDecl *) prevStackFrameCtx->getDecl();
    prevFuncDecl = prevFuncDecl->getCanonicalDecl();

    if (prevFuncDecl != CurFuncDecl)
      continue;

    bool sameArguments = true;

    for (unsigned i = 0; sameArguments && i < CurFuncDecl->getNumParams(); ++i) {
      SVal curArg = Call.getArgSVal(i);
      Optional<SVal> prevArg = getStackFrameArg(state, prevStackFrameCtx, i);
      if (!prevArg)
        break;

      sameArguments = sameArguments && compareArgs(C, state, curArg, *prevArg);
    }

    if (sameArguments)
      emitReport(C);
  }
}

bool InfiniteRecursionChecker::compareArgs(CheckerContext &C,
                                           const ProgramStateRef &state,
                                           const SVal &curArg,
                                           const SVal &prevArg) const {
  SValBuilder &sValBuilder = C.getSValBuilder();
  ConstraintManager &constraintManager = C.getConstraintManager();

  SVal argsEqualSVal = sValBuilder.evalBinOp(state, BO_EQ, curArg, prevArg, sValBuilder.getConditionType());
  Optional<DefinedSVal> argsEqual = argsEqualSVal.getAs<DefinedSVal>();

  if (!argsEqual)
    return false;

  ProgramStateRef stateEQ, stateNEQ;
  std::tie(stateEQ, stateNEQ) = constraintManager.assumeDual(state, *argsEqual);

  if (stateNEQ)
    return false;

  return true;
}

ArrayRef<SVal> InfiniteRecursionChecker::getStackFrameArgs(const ProgramStateRef &state,
                                                           const StackFrameContext *stackFrameCtx) const {

}

Optional<SVal> InfiniteRecursionChecker::getStackFrameArg(const ProgramStateRef &state,
                                                const StackFrameContext *stackFrameCtx,
                                                unsigned int argIdx) const {
  const FunctionDecl *functionDecl = stackFrameCtx->getDecl()->getAsFunction();
  unsigned numArgs = functionDecl->getNumParams();
  if (numArgs > 0 && argIdx < numArgs) {
    const VarDecl *argDecl = functionDecl->parameters()[argIdx];
    const Loc argLoc = state->getLValue(argDecl, stackFrameCtx);
    SVal argSVal = state->getSVal(argLoc);
    return Optional<SVal>(argSVal);
  }
  return None;
}

bool InfiniteRecursionChecker::wantsRegionChangeUpdate(ProgramStateRef State,
                                                       const LocationContext *LCtx) const {
  return false;
}

ProgramStateRef InfiniteRecursionChecker::checkRegionChanges(ProgramStateRef State,
                                     const InvalidatedSymbols *Invalidated,
                                     ArrayRef<const MemRegion *> ExplicitRegions,
                                     ArrayRef<const MemRegion *> Regions,
                                     const CallEvent *Call,
                                     const LocationContext *LCtx) const {
  return State;
}

void InfiniteRecursionChecker::emitReport(CheckerContext &C) const {
  if (!BT)
    BT.reset(new BugType(this, "Infinite recursion detected", "InfiniteRecursionChecker"));

  ExplodedNode *node = C.generateErrorNode();
  if (!node)
    return;

  auto report = llvm::make_unique<BugReport>(*BT, BT->getName(), node);
  C.emitReport(std::move(report));
}

void ento::registerInfiniteRecursionChecker(CheckerManager &mgr) {
  mgr.registerChecker<InfiniteRecursionChecker>();
}

