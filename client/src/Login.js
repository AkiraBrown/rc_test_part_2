import React, { useState, useEffect } from "react";
import { jwtDecode } from "jwt-decode";
import axios from "axios";
import checkToken from "./utils/CheckToken";
import Cookie from "js-cookie";

const SignInForm = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (checkToken()) {
      handleProtected();
    }
  }, []);
  async function handleProtected() {
    try {
      const response = await axios.get("http://localhost:3001/protected", {
        headers: {
          Authorization: `Bearer ${Cookie.get("jwtToken")}`,
        },
        withCredentials: true,
      });
      setMessage(response.data.message);
    } catch (error) {
      console.log(error);
      setMessage("Bad Token: ", error);
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post("http://localhost:3001/login", {
        username,
        password,
      });
      setMessage(`Success! Jwt token => ${response.data.token}`);
      Cookie.set("jwtToken", response.data.token, {
        secure: true,
        expires: jwtDecode(response.data.token).exp,
        sameSite: "Strict",
      });
    } catch (error) {
      setMessage("Login failed. Please check your credentials.");
      console.error("Error logging in:", error);
    }
  };

  return (
    <div>
      <h2>Sign In</h2>
      <form onSubmit={handleSubmit}>
        <div>
          There is no database and users: Please user the following to emulate
          your login experience
          <br />
          username: admin
          <br />
          password: Use the password you've set in your environment variables.
          Must comply with standard password rules
        </div>
        <br />
        <div>
          <label>Username:</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            pattern="[A-Za-z0-9\s]+"
            required
          />
        </div>
        <br />
        <div>
          <label>Password:</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={8}
            title="Need a minimum length of 8"
          />
        </div>
        <br />
        <button type="submit">Sign In</button>
      </form>
      <br />
      {message && <p>{message}</p>}
    </div>
  );
};

export default SignInForm;
