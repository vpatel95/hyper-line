import React from "react";
import ReactDOM from "react-dom";
import { BrowserRouter, Route, Switch, Redirect } from "react-router-dom";

import "assets/plugins/nucleo/css/nucleo.css";
import "@fortawesome/fontawesome-free/css/all.min.css";
import "assets/scss/hyperline-controller.scss";

import AuthLayout from "layouts/Auth.js";
import DashboardLayout from "layouts/Dashboard.js";

ReactDOM.render(
  <BrowserRouter>
    <Switch>
      <Route path="/dashboard" render={props => <DashboardLayout {...props} />} />
      <Route path="/auth" render={props => <AuthLayout {...props} />} />
      <Redirect from="/" to="/auth/login" />
    </Switch>
  </BrowserRouter>,
  document.getElementById("root")
);
