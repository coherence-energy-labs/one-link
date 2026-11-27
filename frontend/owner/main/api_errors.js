  // Build a richer Error object so callers can get both the short
  // headline and the suggested next step. Server returns
  // {error, hint, code} for translated failures.
  function _apiError(j, status) {
    // v0.21.x: when the server returns a structured {error, hint, code},
    // use that. When it doesn't (5xx with no body, network failure
    // before any response), synthesize a plain-English default keyed
    // on the HTTP status so users see actionable text instead of
    // 'request failed (502)'.
    let headline = j && (j.error || j.message);
    let hint = j && j.hint;
    if (!headline) {
      if (status === 401 || status === 403) {
        headline = "One Link forgot who you are.";
        hint = hint || "Try refreshing the page or reopening from the system tray.";
      } else if (status === 404) {
        headline = "That isn't on this device.";
        hint = hint || "It may have been deleted, or the other device hasn't synced yet.";
      } else if (status === 408 || status === 504) {
        headline = "Took too long to answer.";
        hint = hint || "The other device might be offline. Try again in a moment.";
      } else if (status === 413) {
        headline = "That's too big to send right now.";
        hint = hint || "Try a smaller file, or wait for the larger-files path to be enabled.";
      } else if (status === 429) {
        headline = "Slowing things down for a second.";
        hint = hint || "You did the same thing many times in a row. Wait a moment, then try again.";
      } else if (status >= 500 && status < 600) {
        headline = "Something went wrong on this device.";
        hint = hint || "Try again. If it keeps happening, check Settings → About → 'Show daemon log location' for clues.";
      } else if (status === 0) {
        // Browser-side network error before any HTTP response.
        headline = "Can't reach One Link right now.";
        hint = hint || "Make sure the daemon is running. Try restarting it from the system tray.";
      } else {
        headline = `Something went wrong (${status}).`;
      }
    }
    const err = new Error(headline);
    err.status = status;
    err.code = j && j.code || null;
    err.hint = hint || null;
    // v0.7.x: surface the underlying exception text on catch-all
    // 500s so the user (and us) can see what actually failed,
    // instead of just "Send didn't work."
    // v0.21.x: accept both `error_detail` (legacy) AND `detail`
    // (newer endpoints) so the actual exception text always reaches
    // the user. Without this, catch-all 500s show as opaque headlines.
    err.error_detail = (
        (j && (j.error_detail || j.detail)) || null
    );
    return err;
  }

