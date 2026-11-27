  function _dispatchPostIdentityFlow() {
    // Runs once per page, and only with an unlocked identity.
    if (!peerIdentity.beginPostIdentityFlow()) return;
    // 2026-05-23: order matters. Cert-authed reconnect MUST be
    // checked before _setupDeviceInviteQuery so a Safari reload
    // with the old pair URL in history doesn't re-claim a
    // 30-min-expired invite when a permanent cert is already
    // sitting in localStorage. The _hasReturningPair flag is
    // already false when there's a fresh ?pair= query OR no cert
    // exists, so this is safe.
    if (_pairQuery) {
      _runAutoPairFlow(_pairQuery).catch((e) => {
        console.error("autopair failed", e);
        _autopairSetState(
          "bad", "failed",
          `Pair flow crashed: ${e && e.message ? e.message : e}`,
        );
      });
    } else if (_hasReturningPair) {
      _attemptReloginWithStoredCert().then((handoff) => {
        if (handoff) {
          // Strip any stale pair-query from the URL so a future
          // reload doesn't try the relogin-then-stale-claim dance
          // again.
          try {
            if (location.search) {
              history.replaceState(
                null, "", location.pathname + location.hash,
              );
            }
          } catch {}
          _runAutoPairFlow(handoff).catch((e) => {
            console.error("autopair after relogin failed", e);
            _autopairSetState(
              "bad", "failed",
              `Reconnect crashed: ${e && e.message ? e.message : e}`,
            );
          });
        }
      });
    } else if (_setupDeviceInviteQuery) {
      _runSetupDeviceInviteFlow(_setupDeviceInviteQuery).catch((e) => {
        console.error("setup device invite failed", e);
        _selfMeshEnrollSetState(
          "bad", "failed",
          `Setup invite flow crashed: ${e && e.message ? e.message : e}`,
        );
      });
    } else if (_selfMeshQuery) {
      _runSelfMeshInviteFlow(_selfMeshQuery).catch((e) => {
        console.error("self-mesh invite failed", e);
        _selfMeshEnrollSetState(
          "bad", "failed",
          `Invite flow crashed: ${e && e.message ? e.message : e}`,
        );
      });
    }
  }

  boot().then(() => {
    _dispatchPostIdentityFlow();
  }).catch((error) => {
    _showIdentityStorageFailure(error);
  });
