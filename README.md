# Multi-User-Blog
Multi-User Blog Project for Udacity Full-Stack Web Development Nanodegree

## Requirements
This guide assumes you have the following installed:
+ [Conda](https://conda.io/docs/user-guide/install/index.html)
+ [Git](https://git-scm.com/)


## Instructions
1. Clone git repository: `git clone https://github.com/alexbrocklebank/MultiUserBlog.git`.
2. Open command prompt or terminal in MultiUserBlog folder.
1. Create conda environment: `conda create -n blog_env --file package-list.txt`.
1. Activate conda environment by using the appropriate command for your operating system: `activate blog_env` for Windows or `source activate blog_env` for Mac/Linux users.
2. Install `conda install -c pmlandwehr appengine`.
1. Install Google App Engine through the Google Cloud SDK by following [these instructions](https://cloud.google.com/sdk/docs/).
1. Install Google App Engine components by entering `gcloud components install app-engine-python` and `gcloud components install app-engine-python-extras` while in the blog_env conda environment.
1. Set up the app with `gcloud app setup`.
1. Run local server with the command: `dev_appserver blog/app.yaml`
2. Navigate to `localhost:8080/blog` in a browser.


## Live Website
Visit the live blog via [this public link](https://helloworld-150803.appspot.com/blog)

## Frameworks Used
Google App Engine
Jinja2
Bootstrap 3

## Features
+ Secure sign-in with salted and hashed passwords
+ Disallows duplicate users
+ Login/Logout links available when necessary
+ Logged in users can create new blog entries and only edit/delete their own
+ Users cannot like their own posts
+ Users can only like an entry once
+ Templates used to keep site design uniform
+ Bootstrap used for structure and flexibility

## Future Improvements
+ Ability to select/change the site theme
+ Article search funtion
+ Edit and Delete comments
