import React from "react";
import axios from "axios";
import store from "store";
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

// reactstrap components
import {
    Button, Card, CardHeader, CardBody,
    FormGroup, Form, FormFeedback,
    Input, InputGroupAddon, InputGroupText,
    InputGroup, Col
} from "reactstrap";

class Register extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            email : '',
            name : '',
            password : '',
            passwordConfirm : '',
            username : '',
            valid : { },
        }

        this.handleChange = this.handleChange.bind(this);
    }

    handleChange = async (event) => {
        const { target } = event;
        const value = target.type === 'checked' ? target.checked : target.value;
        const { name } = target;
        await this.setState({
            [ name ] : value,
        });
    }

    register(e) {

        const { email, name, password, username } = this.state;
        const { history } = this.props;

        e.preventDefault();
        axios.post("/api/v1/auth/register", {
            email: email,
            name: name,
            username: username,
            password: password
        }).then((res) => {
            store.set("loggedIn", true);
            history.push("/dashboard/home");
        }, (error) => {
            toast.error(error.response.data.message);
        });
    }
    render() {
        const { email, password, name, username, passwordConfirm } = this.state;
        return (
            <>
                <Col lg="6" md="8">
                    <Card className="bg-secondary shadow border-0">
                        <CardHeader className="bg-transparent pb-5">
                            <div className="text-muted text-center mt-2 mb-4">
                                <small>Sign up with</small>
                            </div>
                            <div className="text-center">
                                <Button className="btn-neutral btn-icon mr-4" color="default" href="#pablo" onClick={e => e.preventDefault()} >
                                    <span className="btn-inner--icon">
                                        <img alt="..." src={require("assets/img/icons/common/github.svg")} />
                                    </span>
                                    <span className="btn-inner--text">Github</span>
                                </Button>
                                <Button className="btn-neutral btn-icon" color="default" href="#pablo" onClick={e => e.preventDefault()} >
                                    <span className="btn-inner--icon">
                                        <img alt="..." src={require("assets/img/icons/common/google.svg")} />
                                    </span>
                                    <span className="btn-inner--text">Google</span>
                                </Button>
                            </div>
                        </CardHeader>
                        <CardBody className="px-lg-5 py-lg-5">
                            <div className="text-center text-muted mb-4">
                                <small>Or sign up with credentials</small>
                            </div>
                            <Form role="form" onSubmit={(e) => this.register(e) }>
                                <FormGroup>
                                    <InputGroup className="input-group-alternative mb-3">
                                        <InputGroupAddon addonType="prepend">
                                            <InputGroupText>
                                                <i className="ni ni-hat-3" />
                                            </InputGroupText>
                                        </InputGroupAddon>
                                        <Input placeholder="Name" name="name" type="text"
                                            value={ name }
                                            onChange={ (e) => this.handleChange(e) }
                                        />
                                    </InputGroup>
                                </FormGroup>
                                <FormGroup>
                                    <InputGroup className="input-group-alternative mb-3">
                                        <InputGroupAddon addonType="prepend">
                                            <InputGroupText>
                                                <i className="ni ni-single-02" />
                                            </InputGroupText>
                                        </InputGroupAddon>
                                        <Input placeholder="Username" name="username" type="text"
                                            value={ username }
                                            onChange={ (e) => this.handleChange(e) }
                                        />
                                    </InputGroup>
                                </FormGroup>
                                <FormGroup>
                                    <InputGroup className="input-group-alternative mb-3">
                                        <InputGroupAddon addonType="prepend">
                                            <InputGroupText>
                                                <i className="ni ni-email-83" />
                                            </InputGroupText>
                                        </InputGroupAddon>
                                        <Input placeholder="Email" name="email" type="email"
                                            value={ email }
                                            onChange={(e) => this.handleChange(e) }
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
                                        <Input placeholder="Password" name="password" type="password"
                                            value={ password }
                                            onChange={(e) => this.handleChange(e) }
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
                                        <Input placeholder="Confirm Password" name="passwordConfirm" type="password"
                                            value={ passwordConfirm }
                                            onChange={(e) => this.handleChange(e) }
                                        />
                                        <FormFeedback valid>
                                            Passwords Match
                                        </FormFeedback>
                                        <FormFeedback>
                                            Passwords do not Match
                                        </FormFeedback>
                                    </InputGroup>
                                </FormGroup>
                                <div className="text-center">
                                    <Button className="mt-4" color="primary" type="submit"> Create account </Button>
                                </div>
                            </Form>
                        </CardBody>
                    </Card>
                </Col>
            </>
        );
    }
}

export default Register;
