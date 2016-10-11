// JavaScript source code

var MyChart = angular.module("MyChart", []);
MyChart.controller('Chart_1', function Chart_1($scope, $http) {

    console.log("hi i am in control");

        $http.get('/Chart_1').success(function (response) {

            console.log("i get the data i requested");
         
            var aData = response;
            var seriesData = {
                Date_1: [],
                Shoppnig_1: [],
                Parking_Lot_1: [],
                Checked_Out_1: [],
                Trolley_Bay_1: []



            };
            console.log(aData.length);
           for (var n = 0; n < aData.length; n++) {

                seriesData['Date_1'].push(aData[n]['Date']);
                seriesData['Shoppnig_1'].push(aData[n]['Shoppnig']);
                seriesData['Parking_Lot_1'].push(aData[n]['ParkingLot']);
                seriesData['Checked_Out_1'].push(aData[n]['CheckedOut']);
                seriesData['Trolley_Bay_1'].push(aData[n]['TrolleyBay']);
            }

            var startdate = 1453421700000;
            // Render the chart using the data from Mongo
            var myconfig = {
                "graphset": [
                                    {

                                        "x": "5%",
                                        "y": "10%",
                                        "height": "40%",
                                        "width": "90%",

                                        "type": "line",
                                        "stacked": false,
                                        "utc": true,

                                        "zoom": { "shared": true },

                                        "title": { "text": "Cart Locations" },


                                        "legend": {
                                            "type": "line",
                                            "border-radius": 5,
                                            "border-width": 0,
                                            "shadow": 0,
                                            "item": { "font-size": "12px" },
                                            "vertical-labels": true
                                        },

                                        "scale-x": {
                                            "shadow": 0,
                                            "zooming": true,
                                            "tick": {},
                                            "guide": {},
                                            "item": {},
                                            minValue: startdate,

                                            step: 60000, //unix time in milliseconds (this is a one minute step)
                                            // minValue: 1453421700000, //unix time in milliseconds
                                            // step: 60000, //unix time in milliseconds (this is a one minute step)

                                            "transform": {
                                                "type": "date",

                                                "all": "%D, %d %M<br />%h:%i %A",
                                                "guide": { "visible": false },
                                                "item": { "visible": false }
                                            },

                                            "label": { "visible": false },
                                            "minor-ticks": 0
                                        },

                                        "scale-y": {
                                            "blended": true,
                                            "offset-start": "50%",
                                            "label": { "text": "In Store" },
                                            "guide": { "line-style": "dashed" },
                                            "item": { "font-size": 10 },
                                            "shadow": 0,
                                            "minor-ticks": 0,
                                            "tick": {},
                                        },

                                        "scale-y-2": {

                                            "blended": true,
                                            "offset-end": "60%",
                                            "placement": "default",
                                            "-values": "0:10:5",

                                            "label": { "text": "Outside" },
                                            "guide": { "line-style": "dashed" },
                                            "item": { "font-size": 10 },
                                            "shadow": 0,
                                            "minor-ticks": 0,
                                            "tick": {},
                                        },

                                        "crosshair-x": {
                                            "shared": true,
                                            "line-color": "#f6f7f8",
                                            "plot-label": {
                                                "border-radius": "5px",
                                                "border-width": "1px",
                                                "padding": "10px",
                                                "font-weight": "bold"
                                            },
                                            "scale-label": {
                                                "border-radius": "5px"
                                            }
                                        },

                                        "tooltip": { "visible": false },

                                        "plot": {
                                            "tooltip-text": "%t views: %v<br>%k",
                                            "shadow": 0,
                                            "line-width": 0,
                                            "marker": { "size": 0, "border-width": 0, "shadow": 0 },
                                            "hover-marker": {
                                                "type": "circle",
                                                "size": 4,
                                                "border-width": "1px"
                                            }
                                        },

                                        "series": [
                                            {
                                                'text': 'Shopping Lot',

                                                "values": seriesData['Shoppnig_1'],
                                                "type": "area",
                                                "line-width": 2,
                                                "scales": "scale-x,scale-y-2",
                                            },
                                            {
                                                'text': 'Parking Lot',
                                                "values": seriesData['Parking_Lot_1'],
                                                "type": "area",
                                                "line-width": 2,
                                                "scales": "scale-x,scale-y-2",
                                            },
                                            {
                                                'text': 'Checked Out',
                                                "values": seriesData['Checked_Out_1'],
                                                "type": "area",
                                                "line-width": 2,
                                                "scales": "scale-x,scale-y",
                                            },
                                            {
                                                'text': 'Trolley Bay',
                                                "values": seriesData['Trolley_Bay_1'],
                                                "type": "area",
                                                "line-width": 2,
                                                "scales": "scale-x,scale-y",
                                            }
                                        ],
                                    }


                ]
            }
            zingchart.render({
                id: "myChart",
                width: "100%",
                data: myconfig,
                height: 900,

            });

        });

    $scope.Login = function () {

        console.log($scope.Carto);


        $http.post('/Chart_1', $scope.user).success(function (response) {

            var index = response
            window.location = index;

            if (response = "Not Ok") {


            }

            //console.log(response);

            //   window.open(response);
            //if (response = "OK")

            //  window.open('Chart.html');
            //   refresh();

        });

    };
});
