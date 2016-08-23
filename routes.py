#Google app engine imports
import webapp2

#TODO take out once refactoring is done
import main

def routes():
    """
    function to organize all of the routes
    """
    app = webapp2.WSGIApplication([('/', main.Main),
                               ('/posts', main.Posts),
                               ('/create', main.CreatePost),
                               ('/login', main.Login),
                               ('/logout', main.Logout),
                               ('/posts/([0-9]+)', main.Posts),
                               ('/register', main.Register),
                               ('/comment', main.Comment)],
                              debug=True)
    return app
