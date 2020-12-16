import Dashboard from "views/Dashboard.js";
import Profile from "views/Profile.js";
import Register from "views/Register.js";
import Login from "views/Login.js";

var routes = [
  {
    path: "/home",
    name: "Dashboard",
    icon: "ni ni-tv-2 text-primary",
    component: Dashboard,
    layout: "/dashboard"
  }, {
    path: "/user-profile",
    name: "User Profile",
    icon: "ni ni-single-02 text-yellow",
    component: Profile,
    layout: "/dashboard"
  }, {
    path: "/login",
    name: "Login",
    icon: "ni ni-key-25 text-info",
    component: Login,
    layout: "/auth"
  }, {
    path: "/register",
    name: "Register",
    icon: "ni ni-circle-08 text-pink",
    component: Register,
    layout: "/auth"
  }
];

export default routes;
