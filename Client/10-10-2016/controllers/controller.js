function AppCtrl($scope, $http) {
	console.log("hello Server.js");

	var refresh = function() {
		$http.get('/user').success(function(response) {
			console.log("I get the data I received");
			$scope.user = response; 
			$scope.carto = "";
		})
	};
	refresh();

	$scope.addUser = function() {
		 console.log($scope.user);
		 $http.post('/user', $scope.carto).success(function(response) {
		 	console.log(response);
		 	refresh();
		 });
	}

	$scope.remove = function(id) {
		console.log(id);
		$http.delete('/user/' + id).success(function(response) {
			refresh();
		});
	};

	$scope.edit = function(id) {
		console.log(id);
		$http.get('/user/' + id).success(function(response) {
			$scope.carto = response;
		});
	};

	$scope.update = function() {
		console.log($scope.carto._id);
		$http.put('/user/' + $scope.carto._id, $scope.carto).success(function(response) {
			refresh();
		});
	};
	
}

