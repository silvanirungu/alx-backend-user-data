#!/usr/bin/env python3

"""
Definition of session expiry class
"""
from datetime import time
from os import getenv

from api.v1.auth.auth import Auth


class SessionExpAuth(Auth):
    """
    Implement Session Expiry Authorization protocol methods
    """

    def __init__(self):
        """
        Initialize SessionExpAuth
        """
        super().__init__()
        try:
            self.session_duration = int(getenv("SESSION_DURATION"))
        except Exception:
            self.session_duration = 0

    def create_session(self, user_id: str = None) -> str:
        """
        Creates a Session ID for a user with id user_id
        Args:
            user_id (str): user's user id
        Return:
            None is user_id is None or not a string
            Session ID in string format
        """
        if user_id is None or not isinstance(user_id, str):
            return None
        id = super().create_session(user_id)
        if id is None:
            return None
        self.user_id_by_session_id[id] = {"user_id": user_id, "created_at": time.time()}
        return id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Returns a user ID based on a session ID
        Args:
            session_id (str): session ID
        Return:
            user id or None if session_id is None or not a string
        """
        if session_id is None or not isinstance(session_id, str):
            return None
        session = self.user_id_by_session_id.get(session_id)
        if session is None:
            return None
        if self.session_duration <= 0:
            return session.get("user_id")
        if time.time() - session.get("created_at") > self.session_duration:
            return None
        return session.get("user_id")
