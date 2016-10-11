var MyApp = angular.module("MyApp", []);

MyApp.controller('carttronics_login', function carttronics_login($scope, $http) {
    
    console.log("hi i am in control");
    var refresh = function () {
        $http.get('/carttronicslogin').success(function (response) {
            
            console.log("i get the data i requested");
            $scope.user = response;
            $scope.carto = "";
        });
    }
    refresh();
    $scope.Login = function () {
        
        console.log($scope.user);
     
       
        $http.post('/carttronicslogin', $scope.user).success(function (response) {
            
            var index = response
            window.location = index;

            if (response = "not") { 
                console.log("Please enter valid email and password");
            }

            //console.log(response);
           
         //   window.open(response);
            //if (response = "OK")
                
              //  window.open('Chart.html');
         //   refresh();

        });

    };
});
