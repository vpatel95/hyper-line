import React from "react";
import { Route, Switch, Redirect } from "react-router-dom";
import { Container } from "reactstrap";
import { ToastContainer } from "react-toastify";

import DashboardNavbar from "components/Navbars/DashboardNavbar.js";
import DashboardFooter from "components/Footers/DashboardFooter.js";
import Sidebar from "components/Sidebar/Sidebar.js";

import routes from "routes.js";

class Dashboard extends React.Component {
  componentDidUpdate(e) {
    document.documentElement.scrollTop = 0;
    document.scrollingElement.scrollTop = 0;
    this.refs.mainContent.scrollTop = 0;
  }
  getRoutes = routes => {
    return routes.map((prop, key) => {
      if (prop.layout === "/dashboard") {
        return (
          <Route
            path={prop.layout + prop.path}
            component={prop.component}
            key={key}
          />
        );
      } else {
        return null;
      }
    });
  };
  getBrandText = path => {
    for (let i = 0; i < routes.length; i++) {
      if (
        this.props.location.pathname.indexOf(
          routes[i].layout + routes[i].path
        ) !== -1
      ) {
        return routes[i].name;
      }
    }
    return "Brand";
  };
  render() {
    return (
      <>
        <Sidebar
          {...this.props}
          routes={routes}
          logo={{
            innerLink: "/dashboard/home",
            imgSrc: require("assets/img/brand/argon-react.png"),
            imgAlt: "..."
          }}
        />
        <div className="main-content" ref="mainContent">
          <DashboardNavbar
            {...this.props}
            brandText={this.getBrandText(this.props.location.pathname)}
          />
          <Switch>
            {this.getRoutes(routes)}
            <Redirect from="*" to="/dashboard/home" />
          </Switch>
          <Container fluid>
            <DashboardFooter />
          </Container>
        </div>
        <ToastContainer />
      </>
    );
  }
}

export default Dashboard;
