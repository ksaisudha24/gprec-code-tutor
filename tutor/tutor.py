import functools

from flask import Blueprint
from flask import flash
from flask import g
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from werkzeug.security import check_password_hash
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash

from tutor.db import get_db

bp = Blueprint("tutor", __name__, url_prefix="/tutor")


def login_required(view):
    """View decorator that redirects anonymous users to the login page."""

    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("tutor.login"))

        return view(**kwargs)

    return wrapped_view


@bp.before_app_request
def load_logged_in_user():
    """If a user id is stored in the session, load the user object from
    the database into ``g.user``."""
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
    else:
        g.user = (
            get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
        )


@bp.route("/register", methods=("GET", "POST"))
def register():
    """Register a new user.
    Validates that the username is not already taken. Hashes the
    password for security.
    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        error = None

        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."
        elif (
            db.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone()
            is not None
        ):
            error = "User {0} is already registered.".format(username)

        if error is None:
            # the name is available, store it in the database and go to
            # the login page
            db.execute(
                "INSERT INTO user (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            db.commit()
            return redirect(url_for("tutor.login"))

        flash(error)

    return render_template("auth/register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    """Log in a registered user by adding the user id to the session."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        error = None
        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()

        if user is None:
            error = "Incorrect username."
        elif not check_password_hash(user["password"], password):
            error = "Incorrect password."

        if error is None:
            # store the user id in a new session and return to the index
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("tutor.c"))

        flash(error)

    return render_template("auth/login.html")


@bp.route('/')
def welcome():
    return render_template('auth/home.html')

@bp.route("/logout")
def logout():
    """Clear the current session, including the stored user id."""
    session.clear()
    return redirect(url_for("tutor.welcome"))

@bp.route('/newC')
def c():
    return render_template('auth/newC.html')

@bp.route('/algorithm')
def algorithm():
    return render_template('auth/Algorithm.html')

@bp.route('/getting-started')
def start():
    return render_template('auth/GettingStarted.html')

@bp.route('/variables')
def variables():
    return render_template('auth/Variables.html')

@bp.route('/constants')
def constants():
    return render_template('auth/Constants.html')

@bp.route('/keywords')
def keywords():
    return render_template('auth/Keywords.html')

@bp.route('/datatypes')
def datatypes():
    return render_template('auth/Datatypes.html')

@bp.route('/operators')
def operators():
    return render_template('auth/Operators.html')

@bp.route('/program')
def program():
    return render_template('auth/FirstCProgram.html')

@bp.route('/decision')
def decision():
    return render_template('auth/Decision.html')

@bp.route('/loop')
def loop():
    return render_template('auth/Loop.html')

@bp.route('/jump')
def jump():
    return render_template('auth/Jump.html')

@bp.route('/arrays')
def arrays():
    return render_template('auth/Arrays.html')

@bp.route('/strings')
def strings():
    return render_template('auth/Strings.html')

@bp.route('/pointers')
def pointers():
    return render_template('auth/Pointers.html')

@bp.route('/functions')
def functions():
    return render_template('auth/Functions.html')

@bp.route("/discussions")
def index():
    """Show all the posts, most recent first."""
    db = get_db()
    posts = db.execute(
        "SELECT p.topic_id, title, body, created, author_id, username"
        " FROM post p JOIN user u ON p.author_id = u.id"
        " ORDER BY created DESC"
    ).fetchall()
    return render_template("blog/discussions.html", posts=posts)

def get_post(id, check_author=True):
    """Get a post and its author by id.
    Checks that the id exists and optionally that the current user is
    the author.
    :param id: id of post to get
    :param check_author: require the current user to be the author
    :return: the post with author information
    :raise 404: if a post with the given id doesn't exist
    :raise 403: if the current user isn't the author
    """
    post = (
        get_db()
        .execute(
            "SELECT p.topic_id, title, body, created, author_id, username"
            " FROM post p JOIN user u ON p.author_id = u.id"
            " WHERE p.topic_id = ?",
            (id,),
        )
        .fetchone()
    )

    if post is None:
        abort(404, "Post id {0} doesn't exist.".format(id))

    #if check_author and post["author_id"] != g.user["id"]:
        #abort(403)

    return post


@bp.route("/create", methods=("GET", "POST"))
@login_required
def create():
    """Create a new post for the current user."""
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        error = None

        if not title:
            error = "Title is required."

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                "INSERT INTO post (title, body, author_id) VALUES (?, ?, ?)",
                (title, body, g.user["id"]),
            )
            db.commit()
            return redirect(url_for("tutor.index"))
    db = get_db()
    posts = db.execute(
        "SELECT p.topic_id, title, body, created, author_id, username"
        " FROM post p JOIN user u ON p.author_id = u.id"
        " ORDER BY created DESC"
    ).fetchall()
    return render_template("blog/createNew.html", posts=posts)


@bp.route("/<int:topic_id>/update", methods=("GET", "POST"))
@login_required
def update(topic_id):
    """Update a post if the current user is the author."""
    post = get_post(topic_id)

    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        error = None

        if not title:
            error = "Title is required."

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                "UPDATE post SET title = ?, body = ? WHERE topic_id = ?", (title, body, topic_id)
            )
            db.commit()
            return redirect(url_for("tutor.index"))
    db = get_db()
    posts = db.execute(
        "SELECT p.topic_id, title, body, created, author_id, username"
        " FROM post p JOIN user u ON p.author_id = u.id"
        " ORDER BY created DESC"
    ).fetchall()

    return render_template("blog/updateNew.html", post=post, posts=posts)


@bp.route("/<int:topic_id>/delete", methods=("POST",))
@login_required
def delete(topic_id):
    """Delete a post.
    Ensures that the post exists and that the logged in user is the
    author of the post.
    """
    get_post(topic_id)
    db = get_db()
    db.execute("DELETE FROM post WHERE topic_id = ?", (topic_id,))
    db.commit()
    return redirect(url_for("tutor.index"))

@bp.route("/<int:topic_id>/viewPost", methods=("GET", "POST"))
@login_required
def comments(topic_id):
    post = get_post(topic_id)
    postcoms = query_db(
        "SELECT * FROM postcomments p JOIN user u ON p.author_id=u.id WHERE topic_id = ?",[topic_id]
    )
    if request.method == "POST":

        comments = request.form["comments"]
        db = get_db()
        db.execute(

                "INSERT INTO postcomments (comments, author_id, topic_id) VALUES (?, ?, ?)",
                (comments, g.user["id"], topic_id),
        )
        db.commit()
        return redirect(url_for("tutor.comments", topic_id=post['topic_id']))

    return render_template("blog/viewPost.html", postcoms=postcoms, post=post)


def query_db(query, args=(), one=False):
    db = get_db()
    cur = db.execute(query, args)
    comms = [dict((cur.description[idx][0], value)
        for idx, value in enumerate(row)) for row in cur.fetchall()[::-1]]
    return (comms[0] if comms else None) if one else comms
