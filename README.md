##Multi-User Blog
A simple blog with user signup
Here's the [link](https://monsey-therapists.appspot.com) to the website. 

Instructions for running application:

1. Install [Cloud SDK](https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python) 
(runs on Linux, Mac OS X and Windows, and requires Python 2.7.x)
2. Extract the file to any location on your file system.
3. Initialize gcloud on the command line from within the sdk directory:
```./google-cloud-sdk/bin/gcloud init```
4. Run the application with the "dev_appserver.py" command, specifying the paths of dev_appserver.py and the application:
For example, 
```~/Documents/programming_software/google-cloud-sdk/bin/dev_appserver.py ./Documents/projects/google_applications/user-signup-154601```
5. When the command executes, it will give you the port where the application is running. View the application in the browser by visiting "http://localhost:8080", "8080" is just an example or a port number.
6. To stop the local server: with Mac OS X or Unix, press Control-C or with Windows, press Control-Break in your command prompt window.
