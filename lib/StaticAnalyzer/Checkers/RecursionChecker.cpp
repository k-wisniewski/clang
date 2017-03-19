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

  bool checkReceiversSameInTopFrame(const CallEvent &CurrentCall,
                                    const StackFrameContext *SFC,
                                    CheckerContext &C) const;

  bool checkReceiversSame(const CallEvent &CurrentCall,
                          const CallEvent &PrevCall,
                          CheckerContext &C) const;

  bool checkThisPointersSameInTopFrame(const CallEvent &CurrentCall,
                                       const StackFrameContext *SFC,
                                       CheckerContext &C) const;

  bool checkThisPointersSame(const CallEvent &CurrentCall,
                             const CallEvent &PrevCall,
                             CheckerContext &C) const;

  bool checkAllArgumentsSameInTopFrame(const CallEvent &CurrentCall,
                                       const StackFrameContext *SFC,
                                       CheckerContext &C) const;

  bool checkAllArgumentsSame(const CallEvent &CurrentCall,
                             const CallEvent &PrevCall,
                             CheckerContext &C) const;

  void checkPreCallImpl(const CallEvent &CurrentCall, CheckerContext &C) const;

  SVal getArgSValInTopFrame(const StackFrameContext *SFC,
                            const unsigned ArgIdx,
                            ProgramStateRef StateMgr) const;

  inline Optional<SVal>
  getObjCMessageReceiverSVal(const StackFrameContext *SFC,
                             CheckerContext& C) const;

  inline Optional<SVal>
  getObjCMessageReceiverSValInTopFrame(const StackFrameContext *SFC,
                                       CheckerContext& C) const;

  inline Optional<SVal> getThisSVal(const StackFrameContext *SFC,
                                    CheckerContext &C) const;

  inline Optional<SVal> getThisSValInTopFrame(const StackFrameContext *SFC,
                                              CheckerContext& C) const;
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

void RecursionChecker::checkPreCallImpl(const CallEvent &CurrentCall,
                                        CheckerContext &C) const {

  CallEventManager &Mgr = C.getState()->getStateManager().getCallEventManager();
  for (const auto *SFC = C.getStackFrame();
       SFC != nullptr;
       SFC = SFC->getParent()->getCurrentStackFrame()) {
    if (C.getState()->contains<DirtyStackFrames>(SFC))
      return;

    if (CurrentCall.getDecl() != SFC->getDecl())
      continue;

    if (SFC->inTopFrame()) {
      if (isa<ObjCMethodCall>(CurrentCall)
          && !checkReceiversSameInTopFrame( CurrentCall, SFC, C))
        continue;
      else if (!checkThisPointersSameInTopFrame(CurrentCall, SFC, C))
        continue;

      if (checkAllArgumentsSameInTopFrame(CurrentCall, SFC, C))
        emitReport(C);
    } else {
      CallEventRef<> PrevCall = Mgr.getCaller(SFC, C.getState());
      if (isa<ObjCMethodCall>(CurrentCall)
          && !checkReceiversSame(CurrentCall, *PrevCall, C))
        continue;
      else if (!checkThisPointersSame(CurrentCall, *PrevCall, C))
        continue;

      if (checkAllArgumentsSame(CurrentCall, *PrevCall, C))
        emitReport(C);
    };
  }
}

inline SVal
RecursionChecker::getArgSValInTopFrame(const StackFrameContext *SFC,
                                       const unsigned ArgIdx,
                                       ProgramStateRef State) const {
  const FunctionDecl *FunctionDecl = SFC->getDecl()->getAsFunction();
  const ObjCMethodDecl *MethodDecl =
      dyn_cast_or_null<ObjCMethodDecl>(SFC->getDecl());
  unsigned NumArgs = FunctionDecl
                     ? FunctionDecl->getNumParams()
                     : MethodDecl->getSelector().getNumArgs();
  assert(ArgIdx < NumArgs && "Arg access out of range!");
  assert(SFC->inTopFrame() && "For frames that are not top use CallEvent API");

  const VarDecl *ArgDecl = FunctionDecl
                           ? FunctionDecl->parameters()[ArgIdx]
                           : MethodDecl->parameters()[ArgIdx];
  const Loc ArgLoc = State->getLValue(ArgDecl, SFC);
  StoreManager &StoreMgr = State->getStateManager().getStoreManager();
  Store initialStore = StoreMgr.getInitialStore(SFC).getStore();
  return StoreMgr.getBinding(initialStore, ArgLoc);
}

inline bool
RecursionChecker::checkAllArgumentsSameInTopFrame(const CallEvent &CurrentCall,
                                                  const StackFrameContext *SFC,
                                                  CheckerContext &C) const {
  bool SameArgs = true;
  for (unsigned i = 0; SameArgs && i < CurrentCall.getNumArgs(); ++i) {
    SVal CurArg = CurrentCall.getArgSVal(i);
    SVal PrevArg = getArgSValInTopFrame(SFC, i, C.getState());
    SameArgs = SameArgs && compareArgs(CurArg, PrevArg, C);
  }

  return SameArgs;
}
inline bool
RecursionChecker::checkAllArgumentsSame(const CallEvent &CurrentCall,
                                        const CallEvent &PrevCall,
                                        CheckerContext &C) const {
  bool SameArgs = true;
  for (unsigned i = 0; SameArgs && i < CurrentCall.getNumArgs(); ++i) {
    SVal CurArg = CurrentCall.getArgSVal(i);
    SVal PrevArg = PrevCall.getArgSVal(i);
    SameArgs = SameArgs && compareArgs(CurArg, PrevArg, C);
  }

  return SameArgs;
}

inline bool
RecursionChecker::checkThisPointersSameInTopFrame(const CallEvent &CurrentCall,
                                                  const StackFrameContext *SFC,
                                                  CheckerContext &C) const {
  const Optional<SVal> CurThis = getThisArgument(CurrentCall);
  const Optional<SVal> PrevThis = getThisSValInTopFrame(SFC, C);

  return !CurThis || compareArgs(*CurThis, *PrevThis, C);
}

inline bool
RecursionChecker::checkThisPointersSame(const CallEvent &CurrentCall,
                                        const CallEvent &PrevCall,
                                        CheckerContext &C) const {
  const Optional<SVal> CurThis = getThisArgument(CurrentCall);
  const Optional<SVal> PrevThis = getThisArgument(PrevCall);

  return !CurThis || compareArgs(*CurThis, *PrevThis, C);
}

inline bool
RecursionChecker::checkReceiversSameInTopFrame(const CallEvent &CurrentCall,
                                               const StackFrameContext *SFC,
                                               CheckerContext &C) const {
  const ObjCMethodCall *Msg_ = dyn_cast<const ObjCMethodCall>(&CurrentCall);

  const SVal CurReceiver = Msg_->getReceiverSVal();
  const Optional<SVal> PrevReceiver = getObjCMessageReceiverSValInTopFrame(SFC, C);

  return PrevReceiver && *PrevReceiver == CurReceiver;
}

inline bool
RecursionChecker::checkReceiversSame(const CallEvent &CurrentCall,
                                     const CallEvent &PrevCall,
                                     CheckerContext &C) const {
  const ObjCMethodCall *CurMsg = dyn_cast<const ObjCMethodCall>(&CurrentCall);
  const ObjCMethodCall *PrevMsg = dyn_cast<const ObjCMethodCall>(&CurrentCall);

  const SVal CurReceiver = CurMsg->getReceiverSVal();
  const Optional<SVal> PrevReceiver = PrevMsg->getReceiverSVal();

  return PrevReceiver && *PrevReceiver == CurReceiver;
}

inline Optional<SVal>
RecursionChecker::getThisSValInTopFrame(const StackFrameContext *SFC,
                      CheckerContext& C) const {
  const FunctionDecl *FD = SFC->getDecl()->getAsFunction();
  if (!FD)
    return None;
  const CXXMethodDecl *MD = dyn_cast_or_null<CXXMethodDecl>(FD->getParent());
  if (!MD)
    return None;
  Loc ThisLoc = C.getState()->getStateManager()
      .getSValBuilder()
      .getCXXThis(MD, SFC);
  return C.getState()->getSVal(ThisLoc);
}

inline Optional<SVal>
RecursionChecker::getObjCMessageReceiverSVal(const StackFrameContext *SFC,
                                             CheckerContext& C) const {
  const ObjCMessageExpr *messageExpr =
      dyn_cast<ObjCMessageExpr>(SFC->getCallSite());
  return C.getState()->getSVal(messageExpr->getInstanceReceiver(), SFC);
}

inline Optional<SVal>
RecursionChecker::getObjCMessageReceiverSValInTopFrame(const StackFrameContext *SFC,
                                                       CheckerContext& C) const {
  const ObjCMethodDecl *methodDecl = dyn_cast<ObjCMethodDecl>(SFC->getDecl());
  Loc SelfLoc = C.getState()->getLValue(methodDecl->getSelfDecl(), SFC);
  return C.getState()->getSVal(SelfLoc);
}

inline Optional<SVal>
RecursionChecker::getThisSVal(const StackFrameContext *SFC,
                              CheckerContext& C) const {
  const Stmt *S = SFC->getCallSite();
  if (!S)
    return None;
  if (const auto *MCE = dyn_cast<CXXMemberCallExpr>(S))
    return C.getState()->getSVal(MCE->getImplicitObjectArgument(), SFC->getParent());
  else if (const auto *CCE = dyn_cast<CXXConstructExpr>(S))
    return C.getState()->getSVal(CCE, SFC->getParent());
  return None;
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
