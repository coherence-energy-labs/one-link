  async function fetchDaemonPeers() {
    const reply = await _daemonRequest("fetch_peers", {});
    return Array.isArray(reply.peers) ? reply.peers : [];
  }

  async function fetchDaemonMessages(peerFp, limit) {
    const reply = await _daemonRequest("fetch_messages", {
      peer_fp: peerFp,
      limit: limit || 50,
    });
    return Array.isArray(reply.messages) ? reply.messages : [];
  }

  async function fetchDaemonGroups() {
    const reply = await _daemonRequest("fetch_groups", {});
    return Array.isArray(reply.groups) ? reply.groups : [];
  }

  async function fetchDaemonGroupMessages(groupId, limit) {
    const reply = await _daemonRequest("fetch_group_messages", {
      group_id: groupId,
      limit: limit || 50,
    });
    return Array.isArray(reply.messages) ? reply.messages : [];
  }

  async function searchDaemonGroupMessages(groupId, query, limit) {
    const reply = await _daemonRequest("search_group_messages", {
      group_id: groupId,
      query: String(query || "").trim(),
      limit: limit || 50,
    });
    return Array.isArray(reply.messages) ? reply.messages : [];
  }

  async function fetchDaemonGroupDetail(groupId) {
    const reply = await _daemonRequest("fetch_group_detail", {
      group_id: groupId,
    });
    return reply.group || null;
  }

  async function fetchDaemonGroupInviteLink(groupId) {
    return _daemonRequest("group_invite_link", { group_id: groupId });
  }

  async function addDaemonGroupMember(groupId, peerFp) {
    return _daemonRequest("add_group_member", {
      group_id: groupId,
      peer_fp: peerFp,
      role: "member",
    });
  }

  async function removeDaemonGroupMember(groupId, peerFp) {
    return _daemonRequest("remove_group_member", {
      group_id: groupId,
      peer_fp: peerFp,
    });
  }

  async function leaveDaemonGroup(groupId) {
    return _daemonRequest("leave_group", { group_id: groupId });
  }

  async function sendDaemonGroupMessage(groupId, body, opts) {
    const o = opts || {};
    return _daemonRequest("send_group_message", {
      group_id: groupId,
      body,
      reply_to: o.reply_to || null,
    });
  }

  async function reactDaemonGroupMessage(groupId, msgId, emoji, op) {
    return _daemonRequest("react_group_message", {
      group_id: groupId,
      msg_id: msgId,
      emoji,
      op: op || "add",
    });
  }

  async function editDaemonGroupMessage(groupId, msgId, body) {
    return _daemonRequest("edit_group_message", {
      group_id: groupId,
      msg_id: msgId,
      body,
    });
  }

  async function deleteDaemonGroupMessage(groupId, msgId) {
    return _daemonRequest("delete_group_message", {
      group_id: groupId,
      msg_id: msgId,
    });
  }

  async function searchDaemonMessages(peerFp, query, limit) {
    const reply = await _daemonRequest("search_messages", {
      peer_fp: peerFp,
      query: String(query || "").trim(),
      limit: limit || 50,
    });
    return Array.isArray(reply.messages) ? reply.messages : [];
  }

  async function searchDaemonGlobal(query, limit) {
    return _daemonRequest("global_search", {
      query: String(query || "").trim(),
      limit: limit || 10,
    });
  }

  async function reactDaemonMessage(peerFp, msgId, emoji, op) {
    return _daemonRequest("react_message", {
      peer_fp: peerFp,
      msg_id: msgId,
      emoji,
      op: op || "add",
    });
  }

  async function editDaemonMessage(peerFp, msgId, body) {
    return _daemonRequest("edit_message", {
      peer_fp: peerFp,
      msg_id: msgId,
      body,
    });
  }

  async function deleteDaemonMessage(peerFp, msgId) {
    return _daemonRequest("delete_message", {
      peer_fp: peerFp,
      msg_id: msgId,
    });
  }

