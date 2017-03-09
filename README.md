# slock  

```
GET:  
    200 with token: get lock  
    200 without token: suspend and return.
    403: error  
    502: timeout

PUT:  
    200: put lock ok  
    404: put lock error
```
