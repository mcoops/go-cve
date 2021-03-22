Proof of concept: given other sites are using nvd, github, npm etc, none seem to be doing what we want. 


Ensure that the env `GITHUB_AUTH_TOKEN` is set, otherwise github security data will not be synced.

Then simply run `go run cmd/main.go`.

Note: You'll need about 2GB of RAM as we're storing all records in memory. 

```
user 12928  0.4  0.2 2079696 63420 pts/2   Sl+  11:31   0:03 ./main

~2GB
```

TODO:
 - Minimizing or moving to sqlite at some stage
 - Auto refresh GitHub and NVD data