  function backendRecommendationKey(recommendation) {
    if (!recommendation || typeof recommendation !== "object") return "";
    return [
      recommendation.action || "",
      recommendation.reason || "",
      recommendation.route_preference || "",
      recommendation.video_policy || "",
      recommendation.audio_policy || "",
    ].join("|");
  }

  function backendActionAllowed(action, minGapMs) {
    const now = Date.now();
    const last = Number(callUI.backendActionCooldowns[action] || 0);
    if (now - last < minGapMs) return false;
    callState.stampBackendCooldown(action, now);
    return true;
  }

  function rememberBackendRecommendation(recommendation) {
    const key = backendRecommendationKey(recommendation);
    callState.set("lastBackendRecommendation", {
      at_ms: Date.now(),
      ...(recommendation || {}),
    });
    callState.set("lastBackendRecommendationMs", callUI.lastBackendRecommendation.at_ms);
    const changed = key && key !== callUI.lastBackendRecommendationKey;
    if (changed) {
      callState.set("lastBackendRecommendationKey", key);
      reportCallEvent("backend_recommendation_received", {
        reason: String(recommendation.action || "observe"),
        state: String(recommendation.route_preference || "auto"),
      });
    }
    return changed;
  }

  async function applyBackendPathRecommendation(recommendation, metrics) {
    if (!recommendation || typeof recommendation !== "object") return;
    if (!callUI.activeCallId || !media.pc) return;
    const action = String(recommendation.action || "observe").toLowerCase();
    const routePreference = String(recommendation.route_preference || "").toLowerCase();
    rememberBackendRecommendation(recommendation);
    try {
      if (action === "observe" || action === "hold" || action === "watch") return;

      if (routePreference === "relay") {
        mediaState.set("preferRelayNext", true);
        updateOneChip("#call-one-engine", "Relay ready");
      }

      if (action === "revive_playback") {
        if (!backendActionAllowed("revive_playback", 3000)) return;
        reviveRemotePlayback("backend_recommendation");
        reportCallEvent("backend_recommendation_applied", {
          reason: "revive_playback",
          state: routePreference || "auto",
          ok: true,
        });
        return;
      }

      if (action === "downshift") {
        if (!backendActionAllowed("downshift", 6000)) return;
        await tuneOutboundMediaForTau({
          ...(metrics || callUI.lastMetricsSnapshot || {}),
          loss_rate: Math.max(Number(metrics?.loss_rate || callUI.lastMetricsSnapshot?.loss_rate || 0), 0.08),
          rtt_ms: Math.max(Number(metrics?.rtt_ms || callUI.lastMetricsSnapshot?.rtt_ms || 0), 280),
        });
        reportCallEvent("backend_recommendation_applied", {
          reason: "downshift",
          state: "survival",
          ok: true,
        });
        return;
      }

      if (action === "audio_first_repair") {
        if (!backendActionAllowed("audio_first_repair", 7000)) return;
        reviveRemotePlayback("backend_recommendation");
        await tuneOutboundMediaForTau({
          ...(metrics || callUI.lastMetricsSnapshot || {}),
          loss_rate: Math.max(Number(metrics?.loss_rate || callUI.lastMetricsSnapshot?.loss_rate || 0), 0.1),
          rtt_ms: Math.max(Number(metrics?.rtt_ms || callUI.lastMetricsSnapshot?.rtt_ms || 0), 340),
          media_health_strategy: "audio_first",
        });
        reportCallEvent("backend_recommendation_applied", {
          reason: "audio_first_repair",
          state: "survival",
          ok: true,
        });
        repairMediaPath("backend_audio_first_repair").catch(() => {});
        return;
      }

      if (action === "ice_restart") {
        if (!backendActionAllowed("ice_restart", 9000)) return;
        if (typeof media.pc.restartIce === "function") {
          media.pc.restartIce();
          reportCallEvent("ice_restart_requested", {
            reason: "backend_ice_restart",
            state: routePreference || "auto",
          });
        }
        reportCallEvent("backend_recommendation_applied", {
          reason: "ice_restart",
          state: routePreference || "auto",
          ok: true,
        });
        if (media.pc.signalingState === "stable") {
          await sendLocalSdpOffer();
        } else {
          repairMediaPath("backend_ice_restart").catch(() => {});
        }
        return;
      }

      if (action === "renegotiate" || action === "rebuild_peer_connection") {
        if (!backendActionAllowed(action, 9000)) return;
        reportCallEvent("backend_recommendation_applied", {
          reason: "renegotiate",
          state: routePreference || "auto",
          ok: true,
        });
        await repairMediaPath("backend_renegotiate");
      }
    } catch (_) {
      reportCallEvent("backend_recommendation_failed", {
        reason: action,
        state: routePreference || "auto",
      });
    }
  }

  function rememberBackendRecoveryIntent(intent) {
    if (!intent || typeof intent !== "object") return false;
    const key = [
      intent.action || "observe",
      intent.reason || "",
      intent.priority || 0,
      intent.route_preference || "auto",
    ].join("|");
    callState.set("lastRecoveryIntent", {
      at_ms: Date.now(),
      ...intent,
    });
    callState.set("lastRecoveryIntentMs", callUI.lastRecoveryIntent.at_ms);
    const changed = key && key !== callUI.lastRecoveryIntentKey;
    if (changed) {
      callState.set("lastRecoveryIntentKey", key);
      reportCallEvent("recovery_intent_seen", {
        reason: String(intent.action || "observe"),
        state: String(intent.route_preference || "auto"),
        ok: String(intent.action || "observe") === "hold",
      });
    }
    return changed;
  }

  async function applyBackendRecoveryIntent(intent, metrics) {
    if (!intent || typeof intent !== "object") return;
    if (!callUI.activeCallId || !media.pc) return;
    const executableRecoveryIntents = [
      "revive_playback",
      "downshift",
      "audio_first_repair",
      "restart_ice",
      "force_relay",
      "renegotiate",
      "rebuild_peer_connection",
    ];
    const action = String(intent.action || "observe").toLowerCase();
    const routePreference = String(intent.route_preference || "auto").toLowerCase();
    const cooldownMs = Math.max(1000, Number(intent.cooldown_ms || 4000));
    rememberBackendRecoveryIntent(intent);
    if (action === "observe" || action === "hold" || action === "watch") return;
    if (!executableRecoveryIntents.includes(action)) return;
    if (!backendActionAllowed(`intent_${action}`, cooldownMs)) return;
    try {
      const recommendationLike = {
        action: action === "restart_ice" ? "ice_restart" : action,
        reason: intent.reason || action,
        route_preference: routePreference,
        video_policy: intent.video_policy || "auto",
        audio_priority: intent.audio_first === true,
      };
      if (routePreference === "relay" || action === "force_relay") {
        mediaState.set("preferRelayNext", true);
        updateOneChip("#call-one-engine", "Relay repair");
      }
      if (action === "force_relay") {
        recommendationLike.action = "ice_restart";
        recommendationLike.route_preference = "relay";
      }
      await applyBackendPathRecommendation(
        recommendationLike,
        metrics || callUI.lastMetricsSnapshot,
      );
      reportCallEvent("recovery_intent_applied", {
        reason: action,
        state: routePreference || "auto",
        ok: true,
      });
    } catch (_) {
      reportCallEvent("recovery_intent_failed", {
        reason: action,
        state: routePreference || "auto",
      });
    }
  }

  function applyBackendSessionAuthority(session) {
    if (!session || typeof session !== "object") return;
    const state = String(session.state || "").toLowerCase();
    if (!state) return;
    const reason = String(session.reason || "").toLowerCase();
    const key = [
      state,
      reason,
      session.sequence || "",
      session.recommendation_action || "",
    ].join("|");
    callState.set("lastSessionAuthority", {
      at_ms: Date.now(),
      ...session,
    });
    callState.set("lastSessionAuthorityMs", callUI.lastSessionAuthority.at_ms);
    if (key !== callUI.lastSessionAuthorityKey) {
      callState.set("lastSessionAuthorityKey", key);
      // doctrine-ok: §3.2.a internal state-machine value; user copy below stays calm.
      reportCallEvent("session_authority_seen", {
        reason: state,
        state: state === "reconnecting" ? "connecting" : state,
        ok: state === "connected" || state === "recovered",
      });
    }
    // doctrine-ok: §3.2.a internal state-machine value; user copy uses
    // "Holding the call..." / "Repairing media path..." (no "Reconnecting").
    if (state === "reconnecting") {
      const label = reason === "transport_disconnected" || reason === "network_offline"
        ? "Holding the call while the path recovers..."
        : "Repairing media path...";
      setReconnectState(true, label);
      return;
    }
    if (state === "degraded") {
      setReconnectState(true, "Call quality is recovering...");
      updateCallQuality("fair", "Recovering media");
      return;
    }
    if (state === "negotiating") {
      updateCallQuality("connecting", "Connecting media");
      return;
    }
    if (state === "connected" || state === "recovered") {
      setReconnectState(false);
      updateCallQuality("good", state === "recovered" ? "Media recovered" : "Good call quality");
      return;
    }
    if (state === "failed") {
      setReconnectState(true, "Repairing media path...");
      updateCallQuality("bad", "Media needs repair");
    }
  }

