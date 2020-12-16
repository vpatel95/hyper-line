import React from "react";
import axios from "axios";
import store from "store";
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

import {
    Button, Card, CardHeader,
    CardBody, FormGroup, Form,
    Input, InputGroupAddon,
    InputGroupText, InputGroup,
    Row, Col
} from "reactstrap";

class Login extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            username : '',
            password : '',
        };

        this.handleChange = this.handleChange.bind(this);
    }

    handleChange = async (event) => {
        const { target } = event;
        const value = target.type === 'checkbox' ? target.checked : target.value;
        const { name } = target;
        await this.setState({
            [ name ] : value,
        });
    }

    login(e) {
        e.preventDefault();

        const { username, password } = this.state;
        const { history } = this.props;

        axios.post('/api/v1/auth/login', {
            username: username,
            password: password
        })
        .then((res) => {
            store.set('loggedIn', true);
            history.push('/dashboard/home');
        }, (error) => {
            store.set('loggedIn', false);
            toast.error(error.response.data.message);
        });
    }

    render() {
        const { username, password } = this.state;
        return (
            <>
                <Col lg="5" md="7">
                    <Card className="bg-secondary shadow border-0">
                        <CardHeader className="bg-transparent pb-5">
                            <div className="text-muted text-center mt-2 mb-3">
                                <small>Sign in with</small>
                            </div>
                            <div className="btn-wrapper text-center">
                                <Button className="btn-neutral btn-icon" color="default" href="#pablo" onClick={e => e.preventDefault()} >
                                    <span className="btn-inner--icon">
                                        <img alt="..." src={require("assets/img/icons/common/github.svg")} />
                                    </span>
                                    <span className="btn-inner--text">Github</span>
                                </Button>
                                <Button
                                    className="btn-neutral btn-icon" color="default" href="#pablo" onClick={e => e.preventDefault()} >
                                    <span className="btn-inner--icon">
                                        <img alt="..." src={require("assets/img/icons/common/google.svg")} />
                                    </span>
                                    <span className="btn-inner--text">Google</span>
                                </Button>
                            </div>
                        </CardHeader>
                        <CardBody className="px-lg-5 py-lg-5">
                            <div className="text-center text-muted mb-4">
                                <small>Or sign in with credentials</small>
                            </div>
                            <Form className="form" onSubmit={(e) => this.login(e) }>
                                <FormGroup className="mb-3">
                                    <InputGroup className="input-group-alternative">
                                        <InputGroupAddon addonType="prepend">
                                            <InputGroupText>
                                                <i className="ni ni-circle-08" />
                                            </InputGroupText>
                                        </InputGroupAddon>
                                        <Input placeholder="Username" name="username" type="test"
                                            value={ username }
                                            onChange={ (e) => this.handleChange(e) }
                                        />
                                    </InputGroup>
                                </FormGroup>
                                <FormGroup>
                                    <InputGroup className="input-group-alternative">
                                        <InputGroupAddon addonType="prepend">
                                            <InputGroupText>
                                                <i className="ni ni-lock-circle-open" />
                                            </InputGroupText>
                                        </InputGroupAddon>
                                        <Input placeholder="Password" name="password" type="password" autoComplete="new-password"
                                            value={ password }
                                            onChange={ (e) => this.handleChange(e) }
                                        />
                                    </InputGroup>
                                </FormGroup>
                                <div className="custom-control custom-control-alternative custom-checkbox">
                                    <input className="custom-control-input" id=" customCheckLogin" type="checkbox" />
                                    <label className="custom-control-label" htmlFor=" customCheckLogin" >
                                        <span className="text-muted">Remember me</span>
                                    </label>
                                </div>
                                <div className="text-center">
                                    <Button className="my-4" color="primary" type="submit" > Sign in </Button>
                                </div>
                            </Form>
                        </CardBody>
                    </Card>
                    <Row className="mt-3">
                        <Col xs="6">
                            <a className="text-light" href="#pablo" onClick={e => e.preventDefault()} >
                                <small>Forgot password?</small>
                            </a>
                        </Col>
                        <Col className="text-right" xs="6">
                            <a className="text-light" href="#pablo" onClick={e => e.preventDefault()} >
                                <small>Create new account</small>
                            </a>
                        </Col>
                    </Row>
                </Col>
            </>
        );
    }
}

export default Login;
