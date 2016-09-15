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
class InfiniteRecursionChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

  void emitReport(CheckerContext &C) const;

  SVal getStackFrameArg(const ProgramStateRef &state,
                        const StackFrameContext *stackFrameCtx,
                        unsigned int argIdx) const;

  bool compareArgs(CheckerContext &C, const ProgramStateRef &state, const SVal &curArg, const SVal &prevArg) const;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};
}

void InfiniteRecursionChecker::checkPreCall(const CallEvent &Call,
                                            CheckerContext &C) const {

  const FunctionDecl *curFuncDecl = (const FunctionDecl *) C.getStackFrame()->getDecl();

  const ProgramStateRef state = C.getState();

  for (const auto *parentLC = C.getStackFrame()->getParent(); parentLC != nullptr; parentLC = parentLC->getParent()) {
    const StackFrameContext *prevStackFrameCtx = parentLC->getCurrentStackFrame();
    const FunctionDecl *prevFuncDecl = (const FunctionDecl *) prevStackFrameCtx->getDecl();

    if (prevFuncDecl->getIdentifier() != curFuncDecl->getIdentifier())
      continue;

    bool sameArguments = true;
    for (unsigned i = 0; sameArguments && i < curFuncDecl->getNumParams(); ++i) {
      SVal curArg = Call.getArgSVal(i);
      SVal prevArg = getStackFrameArg(state, prevStackFrameCtx, i);

      sameArguments = sameArguments && compareArgs(C, state, curArg, prevArg);
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

SVal InfiniteRecursionChecker::getStackFrameArg(const ProgramStateRef &state,
                                                const StackFrameContext *stackFrameCtx,
                                                unsigned int argIdx) const {
  const Stmt *callSite = stackFrameCtx->getCallSite();
  const CallExpr *callSiteExpr = dyn_cast<CallExpr>(callSite);
  const Expr *argExpr = callSiteExpr->getArg(argIdx);
  SVal prevArg = state->getSVal(argExpr, stackFrameCtx->getParent());
  return prevArg;
}

void InfiniteRecursionChecker::emitReport(CheckerContext &C) const {
  if (!BT)
    BT.reset(new BugType(this, "Infinite recursion detected", "InfiniteRecursionChecker"));
  ExplodedNode *node = C.generateErrorNode();
  auto report = llvm::make_unique<BugReport>(*BT, BT->getName(), node);
  C.emitReport(std::move(report));
}

void ento::registerInfiniteRecursionChecker(CheckerManager &mgr) {
  mgr.registerChecker<InfiniteRecursionChecker>();
}
