import React, { useState, useEffect } from "react";
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
      Cookie.set("jwtToken", response.data.token);
      console.log("Login successful: here's the jwt token ->", response.data);
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
          password: password
        </div>
        <div>
          <label>Username:</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div>
          <label>Password:</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button type="submit">Sign In</button>
      </form>
      {message && <p>{message}</p>}
    </div>
  );
};

export default SignInForm;
