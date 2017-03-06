# slock  

GET:  
    201: get lock  
    suspend: wait and get:  
            200: get ready  
            201: get lock  
    403: error  

PUT:  
    200: put lock ok  
