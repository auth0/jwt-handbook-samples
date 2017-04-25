## Structure

In this example, we have 2 applications:

* app1.com
* app2.com

## Running
Go to each application folder in turn and run:

```sh
npm install
node app.js
```

In order to be able to test SSO correctly, each application must have its own domain. For that, you can edit your `/etc/hosts` and make app1.com and app2.com point to `127.0.0.1`.

For that, open `/etc/hosts` and edits as follows:

````
##
# Host Database
#
# localhost is used to configure the loopback interface
# when the system is booting.  Do not change this entry.
##
127.0.0.1 localhost
255.255.255.255 broadcasthost
::1             localhost
# ...
127.0.0.1 app1.com
127.0.0.1 app2.com
````

Now you can visit [app1.com:3000](http://app1.com:3000) and [app2.com:3001](http://app2.com:3001).
