"""
StreamBox - A YouTube-like video streaming mobile app
========================================================
Single-file Python application built with Kivy/KivyMD.

WHY SINGLE FILE:
A real production system would split this into `backend/` (FastAPI + Postgres)
and `mobile/` (Kivy client hitting the backend over HTTP). Since this was
requested as ONE file, the backend responsibilities (auth, storage, queries)
are implemented as plain Python classes/functions in this same file, backed
by a local SQLite database (`streambox.db`). This means the app is fully
self-contained and works offline out of the box (per the DEMO MODE
requirement), while keeping the same data model you'd use with a real
FastAPI backend. See the bottom of this file / the README notes for how you
would split this back into backend+mobile if you want a networked version.

Run with:  python main.py
Build APK: buildozer -v android debug   (see buildozer.spec)
"""

import os
import time
import uuid
import hashlib
import sqlite3
import datetime
from functools import partial

from kivy.lang import Builder
from kivy.clock import Clock
from kivy.properties import StringProperty, BooleanProperty, NumericProperty
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.uix.video import Video
from kivy.uix.behaviors import ButtonBehavior
from kivy.metrics import dp
from kivy.core.window import Window

from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.card import MDCard
from kivymd.uix.list import OneLineListItem, TwoLineListItem
from kivymd.uix.snackbar import Snackbar
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDFlatButton

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "streambox.db")

# ---------------------------------------------------------------------------
# "BACKEND" LAYER — data models + business logic (would be FastAPI+SQL in a
# networked deployment; here it's local functions hitting SQLite directly).
# ---------------------------------------------------------------------------

class Database:
    """Owns the SQLite connection and schema. Mirrors the tables you'd have
    in a real Postgres-backed FastAPI service: users, channels, videos,
    comments, likes, subscriptions, watch_history, watch_later."""

    def __init__(self, path=DB_PATH):
        self.path = path
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def _create_schema(self):
        c = self.conn.cursor()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                avatar TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                avatar TEXT DEFAULT '',
                subscriber_count INTEGER DEFAULT 0,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS videos (
                id TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                category TEXT DEFAULT 'All',
                thumbnail TEXT DEFAULT '',
                video_url TEXT NOT NULL,
                views INTEGER DEFAULT 0,
                like_count INTEGER DEFAULT 0,
                dislike_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(channel_id) REFERENCES channels(id)
            );

            CREATE TABLE IF NOT EXISTS comments (
                id TEXT PRIMARY KEY,
                video_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(video_id) REFERENCES videos(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS likes (
                user_id TEXT NOT NULL,
                video_id TEXT NOT NULL,
                value INTEGER NOT NULL, -- 1 = like, -1 = dislike
                PRIMARY KEY(user_id, video_id)
            );

            CREATE TABLE IF NOT EXISTS subscriptions (
                user_id TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                PRIMARY KEY(user_id, channel_id)
            );

            CREATE TABLE IF NOT EXISTS watch_history (
                user_id TEXT NOT NULL,
                video_id TEXT NOT NULL,
                watched_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS watch_later (
                user_id TEXT NOT NULL,
                video_id TEXT NOT NULL,
                added_at TEXT NOT NULL,
                PRIMARY KEY(user_id, video_id)
            );
            """
        )
        self.conn.commit()

    def execute(self, query, params=(), commit=False):
        cur = self.conn.cursor()
        cur.execute(query, params)
        if commit:
            self.conn.commit()
        return cur


db = Database()


def now_iso():
    return datetime.datetime.utcnow().isoformat()


def hash_password(password, salt=None):
    salt = salt or uuid.uuid4().hex
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
    return digest, salt


class AuthService:
    """Register/login logic. In a networked version this issues JWTs; here
    it returns a simple in-memory session token tied to the user id."""

    sessions = {}  # token -> user_id

    @staticmethod
    def register(username, email, password):
        if not username or not email or not password:
            return None, "All fields are required."
        if len(password) < 6:
            return None, "Password must be at least 6 characters."
        existing = db.execute(
            "SELECT id FROM users WHERE username=? OR email=?", (username, email)
        ).fetchone()
        if existing:
            return None, "Username or email already in use."
        uid = uuid.uuid4().hex
        pw_hash, salt = hash_password(password)
        db.execute(
            "INSERT INTO users (id, username, email, password_hash, salt, avatar, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (uid, username, email, pw_hash, salt, "", now_iso()),
            commit=True,
        )
        # Every user gets a channel automatically, like a real platform.
        cid = uuid.uuid4().hex
        db.execute(
            "INSERT INTO channels (id, owner_id, name, description, avatar, subscriber_count) "
            "VALUES (?, ?, ?, ?, ?, 0)",
            (cid, uid, username, "Welcome to my channel!", ""),
            commit=True,
        )
        token = AuthService._issue_token(uid)
        return {"user_id": uid, "token": token, "username": username}, None

    @staticmethod
    def login(username_or_email, password):
        row = db.execute(
            "SELECT * FROM users WHERE username=? OR email=?",
            (username_or_email, username_or_email),
        ).fetchone()
        if not row:
            return None, "Invalid username/email or password."
        pw_hash, _ = hash_password(password, row["salt"])
        if pw_hash != row["password_hash"]:
            return None, "Invalid username/email or password."
        token = AuthService._issue_token(row["id"])
        return {"user_id": row["id"], "token": token, "username": row["username"]}, None

    @staticmethod
    def _issue_token(user_id):
        token = uuid.uuid4().hex
        AuthService.sessions[token] = user_id
        return token

    @staticmethod
    def logout(token):
        AuthService.sessions.pop(token, None)

    @staticmethod
    def current_user_id(token):
        return AuthService.sessions.get(token)


class VideoService:
    @staticmethod
    def list_videos(category="All", search=None):
        query = (
            "SELECT v.*, c.name as channel_name, c.avatar as channel_avatar "
            "FROM videos v JOIN channels c ON v.channel_id = c.id WHERE 1=1"
        )
        params = []
        if category and category != "All":
            query += " AND v.category=?"
            params.append(category)
        if search:
            query += " AND (v.title LIKE ? OR c.name LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        query += " ORDER BY v.created_at DESC"
        return db.execute(query, tuple(params)).fetchall()

    @staticmethod
    def get_video(video_id):
        return db.execute(
            "SELECT v.*, c.name as channel_name, c.avatar as channel_avatar, c.id as chan_id "
            "FROM videos v JOIN channels c ON v.channel_id = c.id WHERE v.id=?",
            (video_id,),
        ).fetchone()

    @staticmethod
    def register_view(video_id):
        db.execute("UPDATE videos SET views = views + 1 WHERE id=?", (video_id,), commit=True)

    @staticmethod
    def upload_video(channel_id, title, description, category, video_url, thumbnail=""):
        if not title or not video_url:
            return None, "Title and video file are required."
        vid = uuid.uuid4().hex
        db.execute(
            "INSERT INTO videos (id, channel_id, title, description, category, thumbnail, "
            "video_url, views, like_count, dislike_count, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?)",
            (vid, channel_id, title, description, category, thumbnail, video_url, now_iso()),
            commit=True,
        )
        return vid, None

    @staticmethod
    def toggle_like(user_id, video_id, value):
        existing = db.execute(
            "SELECT value FROM likes WHERE user_id=? AND video_id=?", (user_id, video_id)
        ).fetchone()
        if existing and existing["value"] == value:
            db.execute("DELETE FROM likes WHERE user_id=? AND video_id=?", (user_id, video_id), commit=True)
        elif existing:
            db.execute(
                "UPDATE likes SET value=? WHERE user_id=? AND video_id=?", (value, user_id, video_id), commit=True
            )
        else:
            db.execute(
                "INSERT INTO likes (user_id, video_id, value) VALUES (?, ?, ?)",
                (user_id, video_id, value), commit=True,
            )
        likes = db.execute("SELECT COUNT(*) c FROM likes WHERE video_id=? AND value=1", (video_id,)).fetchone()["c"]
        dislikes = db.execute("SELECT COUNT(*) c FROM likes WHERE video_id=? AND value=-1", (video_id,)).fetchone()["c"]
        db.execute("UPDATE videos SET like_count=?, dislike_count=? WHERE id=?", (likes, dislikes, video_id), commit=True)
        return likes, dislikes

    @staticmethod
    def add_comment(video_id, user_id, text):
        if not text.strip():
            return None, "Comment cannot be empty."
        cid = uuid.uuid4().hex
        db.execute(
            "INSERT INTO comments (id, video_id, user_id, text, created_at) VALUES (?, ?, ?, ?, ?)",
            (cid, video_id, user_id, text.strip(), now_iso()), commit=True,
        )
        return cid, None

    @staticmethod
    def delete_comment(comment_id, user_id):
        row = db.execute("SELECT user_id FROM comments WHERE id=?", (comment_id,)).fetchone()
        if not row or row["user_id"] != user_id:
            return False, "You can only delete your own comments."
        db.execute("DELETE FROM comments WHERE id=?", (comment_id,), commit=True)
        return True, None

    @staticmethod
    def list_comments(video_id):
        return db.execute(
            "SELECT cm.*, u.username FROM comments cm JOIN users u ON cm.user_id = u.id "
            "WHERE cm.video_id=? ORDER BY cm.created_at DESC",
            (video_id,),
        ).fetchall()

    @staticmethod
    def record_history(user_id, video_id):
        db.execute(
            "INSERT INTO watch_history (user_id, video_id, watched_at) VALUES (?, ?, ?)",
            (user_id, video_id, now_iso()), commit=True,
        )

    @staticmethod
    def get_history(user_id):
        return db.execute(
            "SELECT v.*, wh.watched_at FROM watch_history wh "
            "JOIN videos v ON wh.video_id = v.id WHERE wh.user_id=? ORDER BY wh.watched_at DESC",
            (user_id,),
        ).fetchall()

    @staticmethod
    def clear_history(user_id):
        db.execute("DELETE FROM watch_history WHERE user_id=?", (user_id,), commit=True)

    @staticmethod
    def add_watch_later(user_id, video_id):
        db.execute(
            "INSERT OR IGNORE INTO watch_later (user_id, video_id, added_at) VALUES (?, ?, ?)",
            (user_id, video_id, now_iso()), commit=True,
        )

    @staticmethod
    def remove_watch_later(user_id, video_id):
        db.execute("DELETE FROM watch_later WHERE user_id=? AND video_id=?", (user_id, video_id), commit=True)

    @staticmethod
    def get_watch_later(user_id):
        return db.execute(
            "SELECT v.* FROM watch_later wl JOIN videos v ON wl.video_id = v.id WHERE wl.user_id=? "
            "ORDER BY wl.added_at DESC",
            (user_id,),
        ).fetchall()


class ChannelService:
    @staticmethod
    def get_channel(channel_id):
        return db.execute("SELECT * FROM channels WHERE id=?", (channel_id,)).fetchone()

    @staticmethod
    def get_channel_by_owner(user_id):
        return db.execute("SELECT * FROM channels WHERE owner_id=?", (user_id,)).fetchone()

    @staticmethod
    def toggle_subscription(user_id, channel_id):
        existing = db.execute(
            "SELECT 1 FROM subscriptions WHERE user_id=? AND channel_id=?", (user_id, channel_id)
        ).fetchone()
        if existing:
            db.execute(
                "DELETE FROM subscriptions WHERE user_id=? AND channel_id=?", (user_id, channel_id), commit=True
            )
            delta = -1
            subscribed = False
        else:
            db.execute(
                "INSERT INTO subscriptions (user_id, channel_id) VALUES (?, ?)", (user_id, channel_id), commit=True
            )
            delta = 1
            subscribed = True
        db.execute(
            "UPDATE channels SET subscriber_count = subscriber_count + ? WHERE id=?", (delta, channel_id), commit=True
        )
        return subscribed

    @staticmethod
    def is_subscribed(user_id, channel_id):
        return bool(db.execute(
            "SELECT 1 FROM subscriptions WHERE user_id=? AND channel_id=?", (user_id, channel_id)
        ).fetchone())

    @staticmethod
    def subscription_feed(user_id):
        return db.execute(
            "SELECT v.*, c.name as channel_name FROM videos v "
            "JOIN subscriptions s ON v.channel_id = s.channel_id "
            "JOIN channels c ON v.channel_id = c.id "
            "WHERE s.user_id=? ORDER BY v.created_at DESC",
            (user_id,),
        ).fetchall()

    @staticmethod
    def channel_videos(channel_id):
        return db.execute("SELECT * FROM videos WHERE channel_id=? ORDER BY created_at DESC", (channel_id,)).fetchall()


def seed_demo_data():
    """DEMO MODE: populate sample channels/videos so the UI is testable
    immediately after install, with no manual setup. Uses public-domain
    sample MP4s (Big Buck Bunny / Sintel test streams) as placeholders."""
    has_data = db.execute("SELECT COUNT(*) c FROM videos").fetchone()["c"]
    if has_data:
        return
    demo_user, _ = AuthService.register("demo_creator", "demo@streambox.app", "demo123")
    channel = ChannelService.get_channel_by_owner(demo_user["user_id"])
    samples = [
        ("Big Buck Bunny - Official Trailer", "Technology",
         "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"),
        ("Sintel - Short Film", "Education",
         "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/Sintel.mp4"),
        ("Elephants Dream", "Music",
         "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4"),
        ("For Bigger Blazes", "Gaming",
         "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4"),
        ("For Bigger Joyrides", "News",
         "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerJoyrides.mp4"),
        ("For Bigger Escape", "Sports",
         "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerEscape.mp4"),
    ]
    for title, category, url in samples:
        vid, _ = VideoService.upload_video(
            channel["id"], title, f"Sample demo video: {title}", category, url
        )
        # give it some fake initial views so the feed looks alive
        db.execute("UPDATE videos SET views=? WHERE id=?", (uuid.uuid4().int % 50000, vid), commit=True)


seed_demo_data()

# ---------------------------------------------------------------------------
# UI LAYER — Kivy/KivyMD screens
# ---------------------------------------------------------------------------

KV = """
#:import dp kivy.metrics.dp

<VideoCard@MDCard>:
    orientation: "vertical"
    size_hint_y: None
    height: dp(220)
    padding: dp(8)
    spacing: dp(6)
    radius: [16,]
    ripple_behavior: True
    elevation: 1

<CategoryChip@MDChip>:
    size_hint: None, None
    height: dp(34)

<TopBar@MDTopAppBar>:
    elevation: 2

ScreenManager:
    id: sm

    LoginScreen:
        name: "login"
    RegisterScreen:
        name: "register"
    MainScreen:
        name: "main"
    VideoDetailScreen:
        name: "video_detail"
    UploadScreen:
        name: "upload"
    ChannelScreen:
        name: "channel"

<LoginScreen>:
    MDBoxLayout:
        orientation: "vertical"
        padding: dp(24)
        spacing: dp(16)
        md_bg_color: app.theme_cls.bg_normal

        Widget:
            size_hint_y: 0.2

        MDLabel:
            text: "StreamBox"
            font_style: "H4"
            halign: "center"
            bold: True

        MDLabel:
            text: "Sign in to continue"
            halign: "center"
            theme_text_color: "Secondary"

        MDTextField:
            id: login_user
            hint_text: "Username or Email"
            icon_right: "account"

        MDTextField:
            id: login_pass
            hint_text: "Password"
            password: True
            icon_right: "eye-off"

        MDRaisedButton:
            text: "LOG IN"
            pos_hint: {"center_x": 0.5}
            size_hint_x: 1
            on_release: app.do_login(login_user.text, login_pass.text)

        MDFlatButton:
            text: "Don't have an account? Register"
            pos_hint: {"center_x": 0.5}
            on_release: app.root.current = "register"

        MDFlatButton:
            text: "Continue as Guest"
            pos_hint: {"center_x": 0.5}
            on_release: app.continue_as_guest()

        Widget:

<RegisterScreen>:
    MDBoxLayout:
        orientation: "vertical"
        padding: dp(24)
        spacing: dp(14)

        Widget:
            size_hint_y: 0.1

        MDLabel:
            text: "Create Account"
            font_style: "H5"
            halign: "center"
            bold: True

        MDTextField:
            id: reg_user
            hint_text: "Username"

        MDTextField:
            id: reg_email
            hint_text: "Email"

        MDTextField:
            id: reg_pass
            hint_text: "Password (min 6 chars)"
            password: True

        MDRaisedButton:
            text: "REGISTER"
            pos_hint: {"center_x": 0.5}
            on_release: app.do_register(reg_user.text, reg_email.text, reg_pass.text)

        MDFlatButton:
            text: "Already have an account? Log in"
            pos_hint: {"center_x": 0.5}
            on_release: app.root.current = "login"

        Widget:

<MainScreen>:
    MDBoxLayout:
        orientation: "vertical"

        MDTopAppBar:
            title: "StreamBox"
            left_action_items: [["play-box-multiple", lambda x: None]]
            right_action_items: [["magnify", lambda x: app.open_search()], ["bell-outline", lambda x: app.show_snack("No new notifications")], ["theme-light-dark", lambda x: app.toggle_theme()]]

        MDTextField:
            id: search_field
            hint_text: "Search videos or channels"
            size_hint_y: None
            height: dp(48)
            padding: [dp(12), dp(8)]
            on_text_validate: app.search_videos(self.text)

        ScrollView:
            do_scroll_x: False
            MDBoxLayout:
                id: chip_box
                orientation: "horizontal"
                size_hint_y: None
                height: dp(44)
                spacing: dp(8)
                padding: [dp(8), 0]

        MDBottomNavigation:
            id: bottom_nav
            panel_color: app.theme_cls.bg_darkest

            MDBottomNavigationItem:
                name: "home"
                text: "Home"
                icon: "home"
                ScrollView:
                    MDBoxLayout:
                        id: home_feed
                        orientation: "vertical"
                        adaptive_height: True
                        padding: dp(8)
                        spacing: dp(12)

            MDBottomNavigationItem:
                name: "subs"
                text: "Subscriptions"
                icon: "youtube-subscription"
                ScrollView:
                    MDBoxLayout:
                        id: subs_feed
                        orientation: "vertical"
                        adaptive_height: True
                        padding: dp(8)
                        spacing: dp(12)

            MDBottomNavigationItem:
                name: "library"
                text: "Library"
                icon: "video-box"
                ScrollView:
                    MDBoxLayout:
                        id: library_feed
                        orientation: "vertical"
                        adaptive_height: True
                        padding: dp(8)
                        spacing: dp(16)

            MDBottomNavigationItem:
                name: "profile"
                text: "Profile"
                icon: "account-circle"
                MDBoxLayout:
                    id: profile_box
                    orientation: "vertical"
                    padding: dp(24)
                    spacing: dp(12)

<VideoDetailScreen>:
    MDBoxLayout:
        orientation: "vertical"

        MDTopAppBar:
            title: "Now Playing"
            left_action_items: [["arrow-left", lambda x: app.go_back_to_main()]]

        BoxLayout:
            id: player_box
            size_hint_y: None
            height: dp(220)

        ScrollView:
            MDBoxLayout:
                id: detail_box
                orientation: "vertical"
                adaptive_height: True
                padding: dp(12)
                spacing: dp(10)

<UploadScreen>:
    MDBoxLayout:
        orientation: "vertical"

        MDTopAppBar:
            title: "Upload Video"
            left_action_items: [["arrow-left", lambda x: app.go_back_to_main()]]

        MDBoxLayout:
            orientation: "vertical"
            padding: dp(20)
            spacing: dp(14)

            MDTextField:
                id: up_title
                hint_text: "Video Title"

            MDTextField:
                id: up_desc
                hint_text: "Description"
                multiline: True

            MDTextField:
                id: up_category
                hint_text: "Category (Music/Gaming/Education/Technology/News/Sports)"

            MDTextField:
                id: up_url
                hint_text: "Video file path or URL"

            MDRaisedButton:
                text: "UPLOAD"
                pos_hint: {"center_x": 0.5}
                on_release: app.do_upload(up_title.text, up_desc.text, up_category.text, up_url.text)

            MDLabel:
                id: upload_progress_label
                text: ""
                halign: "center"

<ChannelScreen>:
    MDBoxLayout:
        orientation: "vertical"

        MDTopAppBar:
            title: "Channel"
            left_action_items: [["arrow-left", lambda x: app.go_back_to_main()]]

        ScrollView:
            MDBoxLayout:
                id: channel_box
                orientation: "vertical"
                adaptive_height: True
                padding: dp(16)
                spacing: dp(10)
"""


class LoginScreen(Screen):
    pass


class RegisterScreen(Screen):
    pass


class MainScreen(Screen):
    pass


class VideoDetailScreen(Screen):
    pass


class UploadScreen(Screen):
    pass


class ChannelScreen(Screen):
    pass


class ClickableCard(MDCard, ButtonBehavior):
    """MDCard in KivyMD 1.2.0 doesn't inherit ButtonBehavior, so it has no
    on_release event — binding to it silently does nothing (no crash, no
    tap response). This mixes ButtonBehavior in, the same pattern KivyMD
    itself uses for MDChip, so video cards are actually tappable while
    keeping MDCard's rounded/elevated/ripple styling."""
    pass


class StreamBoxApp(MDApp):
    current_token = StringProperty("")
    current_user_id = StringProperty("")
    current_username = StringProperty("Guest")
    is_guest = BooleanProperty(True)
    current_video_id = StringProperty("")

    def build(self):
        self.title = "StreamBox"
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Red"
        self.theme_cls.accent_palette = "Amber"
        Window.softinput_mode = "below_target"
        root = Builder.load_string(KV)
        return root

    def on_start(self):
        self.build_category_chips()
        self.refresh_home_feed()

    # ---------------- Auth ----------------
    def do_login(self, username, password):
        result, error = AuthService.login(username, password)
        if error:
            self.show_snack(error)
            return
        self._apply_session(result)
        self.root.current = "main"
        self.refresh_home_feed()

    def do_register(self, username, email, password):
        result, error = AuthService.register(username, email, password)
        if error:
            self.show_snack(error)
            return
        self._apply_session(result)
        self.root.current = "main"
        self.refresh_home_feed()

    def continue_as_guest(self):
        self.is_guest = True
        self.current_token = ""
        self.current_user_id = ""
        self.current_username = "Guest"
        self.root.current = "main"
        self.refresh_home_feed()

    def _apply_session(self, result):
        self.current_token = result["token"]
        self.current_user_id = result["user_id"]
        self.current_username = result["username"]
        self.is_guest = False

    def do_logout(self):
        AuthService.logout(self.current_token)
        self.current_token = ""
        self.current_user_id = ""
        self.current_username = "Guest"
        self.is_guest = True
        self.root.current = "login"

    def require_login(self):
        if self.is_guest:
            self.show_snack("Please log in to do that.")
            return False
        return True

    # ---------------- Home / Feed ----------------
    def build_category_chips(self):
        main_screen = self.root.get_screen("main")
        chip_box = main_screen.ids.chip_box
        chip_box.clear_widgets()
        from kivymd.uix.chip import MDChip
        categories = ["All", "Music", "Gaming", "Education", "Technology", "News", "Sports"]
        for cat in categories:
            chip = MDChip(text=cat, icon_right="check" if cat == "All" else "")
            chip.bind(on_release=partial(self._on_chip_selected, cat))
            chip_box.add_widget(chip)

    def _on_chip_selected(self, category, *args):
        self.refresh_home_feed(category=category)

    def refresh_home_feed(self, category="All"):
        main_screen = self.root.get_screen("main")
        feed = main_screen.ids.home_feed
        feed.clear_widgets()
        videos = VideoService.list_videos(category=category)
        if not videos:
            feed.add_widget(OneLineListItem(text="No videos found."))
            return
        for v in videos:
            feed.add_widget(self._make_video_card(v))
        self._refresh_subs_feed()
        self._refresh_library()
        self._refresh_profile()

    def search_videos(self, query):
        main_screen = self.root.get_screen("main")
        feed = main_screen.ids.home_feed
        feed.clear_widgets()
        results = VideoService.list_videos(search=query) if query else VideoService.list_videos()
        if not results:
            feed.add_widget(OneLineListItem(text="No results found."))
            return
        for v in results:
            feed.add_widget(self._make_video_card(v))

    def open_search(self):
        main_screen = self.root.get_screen("main")
        main_screen.ids.search_field.focus = True

    def _make_video_card(self, v):
        card = ClickableCard(
            orientation="vertical", size_hint_y=None, height=dp(150),
            padding=dp(10), spacing=dp(4), radius=[14], ripple_behavior=True,
        )
        card.add_widget(TwoLineListItem(
            text=f"{v['title']}",
            secondary_text=f"{v['channel_name']} • {v['views']} views",
        ))
        card.bind(on_release=partial(self.open_video, v["id"]))
        return card

    def open_video(self, video_id, *args):
        self.current_video_id = video_id
        video = VideoService.get_video(video_id)
        VideoService.register_view(video_id)
        if not self.is_guest:
            VideoService.record_history(self.current_user_id, video_id)

        screen = self.root.get_screen("video_detail")
        player_box = screen.ids.player_box
        player_box.clear_widgets()
        player = Video(source=video["video_url"], state="play", options={"eos": "loop"})
        player_box.add_widget(player)

        detail_box = screen.ids.detail_box
        detail_box.clear_widgets()
        detail_box.add_widget(TwoLineListItem(
            text=video["title"], secondary_text=f"{video['channel_name']} • {video['views']} views"
        ))
        row = MDBoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        like_btn = MDFlatButton(text=f"👍 {video['like_count']}")
        like_btn.bind(on_release=lambda *a: self._like(video_id, 1))
        dislike_btn = MDFlatButton(text=f"👎 {video['dislike_count']}")
        dislike_btn.bind(on_release=lambda *a: self._like(video_id, -1))
        sub_state = "Subscribed" if (not self.is_guest and ChannelService.is_subscribed(self.current_user_id, video["chan_id"])) else "Subscribe"
        sub_btn = MDFlatButton(text=sub_state)
        sub_btn.bind(on_release=lambda *a: self._subscribe(video["chan_id"]))
        wl_btn = MDFlatButton(text="+ Watch Later")
        wl_btn.bind(on_release=lambda *a: self._watch_later(video_id))
        row.add_widget(like_btn)
        row.add_widget(dislike_btn)
        row.add_widget(sub_btn)
        row.add_widget(wl_btn)
        detail_box.add_widget(row)
        detail_box.add_widget(OneLineListItem(text=video["description"] or "No description."))

        detail_box.add_widget(OneLineListItem(text="Comments", theme_text_color="Secondary"))
        self.comment_field = None
        if not self.is_guest:
            from kivymd.uix.textfield import MDTextField
            self.comment_field = MDTextField(hint_text="Add a comment...")
            add_btn = MDFlatButton(text="Post")
            add_btn.bind(on_release=lambda *a: self._post_comment(video_id))
            comment_row = MDBoxLayout(size_hint_y=None, height=dp(48))
            comment_row.add_widget(self.comment_field)
            comment_row.add_widget(add_btn)
            detail_box.add_widget(comment_row)

        for c in VideoService.list_comments(video_id):
            item_text = f"{c['username']}: {c['text']}"
            item = OneLineListItem(text=item_text)
            if not self.is_guest and c["user_id"] == self.current_user_id:
                item.bind(on_release=partial(self._delete_comment, c["id"], video_id))
            detail_box.add_widget(item)

        self.root.transition = SlideTransition(direction="left")
        self.root.current = "video_detail"

    def _like(self, video_id, value):
        if not self.require_login():
            return
        VideoService.toggle_like(self.current_user_id, video_id, value)
        self.open_video(video_id)

    def _subscribe(self, channel_id):
        if not self.require_login():
            return
        ChannelService.toggle_subscription(self.current_user_id, channel_id)
        self.open_video(self.current_video_id)

    def _watch_later(self, video_id):
        if not self.require_login():
            return
        VideoService.add_watch_later(self.current_user_id, video_id)
        self.show_snack("Added to Watch Later")

    def _post_comment(self, video_id):
        if not self.require_login() or not self.comment_field:
            return
        _, error = VideoService.add_comment(video_id, self.current_user_id, self.comment_field.text)
        if error:
            self.show_snack(error)
            return
        self.open_video(video_id)

    def _delete_comment(self, comment_id, video_id, *args):
        ok, error = VideoService.delete_comment(comment_id, self.current_user_id)
        if not ok:
            self.show_snack(error)
            return
        self.open_video(video_id)

    def go_back_to_main(self):
        self.root.transition = SlideTransition(direction="right")
        self.root.current = "main"

    # ---------------- Subscriptions / Library / Profile ----------------
    def _refresh_subs_feed(self):
        main_screen = self.root.get_screen("main")
        box = main_screen.ids.subs_feed
        box.clear_widgets()
        if self.is_guest:
            box.add_widget(OneLineListItem(text="Log in to see your subscriptions."))
            return
        videos = ChannelService.subscription_feed(self.current_user_id)
        if not videos:
            box.add_widget(OneLineListItem(text="No videos from subscriptions yet."))
            return
        for v in videos:
            box.add_widget(self._make_video_card(v))

    def _refresh_library(self):
        main_screen = self.root.get_screen("main")
        box = main_screen.ids.library_feed
        box.clear_widgets()
        if self.is_guest:
            box.add_widget(OneLineListItem(text="Log in to see History, Watch Later, and Uploads."))
            return

        box.add_widget(OneLineListItem(text="Watch History", theme_text_color="Secondary"))
        clear_btn = MDFlatButton(text="Clear History")
        clear_btn.bind(on_release=lambda *a: (VideoService.clear_history(self.current_user_id), self._refresh_library()))
        box.add_widget(clear_btn)
        history = VideoService.get_history(self.current_user_id)
        if not history:
            box.add_widget(OneLineListItem(text="No watch history yet."))
        for v in history[:10]:
            box.add_widget(self._make_video_card(v))

        box.add_widget(OneLineListItem(text="Watch Later", theme_text_color="Secondary"))
        wl = VideoService.get_watch_later(self.current_user_id)
        if not wl:
            box.add_widget(OneLineListItem(text="Nothing saved for later."))
        for v in wl:
            box.add_widget(self._make_video_card(v))

        upload_btn = MDFlatButton(text="+ Upload a Video")
        upload_btn.bind(on_release=lambda *a: self.open_upload())
        box.add_widget(upload_btn)

    def _refresh_profile(self):
        main_screen = self.root.get_screen("main")
        box = main_screen.ids.profile_box
        box.clear_widgets()
        if self.is_guest:
            box.add_widget(OneLineListItem(text="You're browsing as a guest."))
            login_btn = MDFlatButton(text="Log In")
            login_btn.bind(on_release=lambda *a: setattr(self.root, "current", "login"))
            box.add_widget(login_btn)
            return
        box.add_widget(TwoLineListItem(text=self.current_username, secondary_text="View your channel"))
        channel_btn = MDFlatButton(text="My Channel")
        channel_btn.bind(on_release=lambda *a: self.open_channel())
        box.add_widget(channel_btn)
        logout_btn = MDFlatButton(text="Log Out")
        logout_btn.bind(on_release=lambda *a: self.do_logout())
        box.add_widget(logout_btn)

    # ---------------- Upload ----------------
    def open_upload(self):
        if not self.require_login():
            return
        self.root.current = "upload"

    def do_upload(self, title, description, category, video_url):
        if not self.require_login():
            return
        channel = ChannelService.get_channel_by_owner(self.current_user_id)
        screen = self.root.get_screen("upload")
        screen.ids.upload_progress_label.text = "Uploading... 0%"

        def fake_progress(step, dt):
            pct = min(100, step * 25)
            screen.ids.upload_progress_label.text = f"Uploading... {pct}%"
            if pct >= 100:
                vid, error = VideoService.upload_video(
                    channel["id"], title, description, category or "All", video_url
                )
                if error:
                    self.show_snack(error)
                    screen.ids.upload_progress_label.text = ""
                else:
                    self.show_snack("Upload complete!")
                    screen.ids.upload_progress_label.text = "Done!"
                    self.refresh_home_feed()
                    Clock.schedule_once(lambda *a: self.go_back_to_main(), 1)

        for i in range(1, 5):
            Clock.schedule_once(partial(fake_progress, i), i * 0.3)

    # ---------------- Channel ----------------
    def open_channel(self):
        channel = ChannelService.get_channel_by_owner(self.current_user_id)
        if not channel:
            self.show_snack("No channel found.")
            return
        screen = self.root.get_screen("channel")
        box = screen.ids.channel_box
        box.clear_widgets()
        box.add_widget(TwoLineListItem(
            text=channel["name"],
            secondary_text=f"{channel['subscriber_count']} subscribers",
        ))
        box.add_widget(OneLineListItem(text=channel["description"] or "No description."))
        box.add_widget(OneLineListItem(text="Uploaded Videos", theme_text_color="Secondary"))
        videos = ChannelService.channel_videos(channel["id"])
        if not videos:
            box.add_widget(OneLineListItem(text="No videos uploaded yet."))
        for v in videos:
            box.add_widget(self._make_video_card(dict(v, channel_name=channel["name"])))
        self.root.current = "channel"

    # ---------------- Utilities ----------------
    def toggle_theme(self):
        self.theme_cls.theme_style = "Light" if self.theme_cls.theme_style == "Dark" else "Dark"

    def show_snack(self, text):
        Snackbar(text=text).open()


if __name__ == "__main__":
    StreamBoxApp().run()