import { jwtDecode } from "jwt-decode";

function checkToken() {
  const jwtToken = window.localStorage.getItem("jwtToken");
  if (jwtToken) {
    const decodedToken = jwtDecode(jwtToken);
    const currentTime = Date.now() / 1000;
    console.log(decodedToken.exp, currentTime);
    if (decodedToken.exp < currentTime) {
      window.localStorage.removeItem("jwtToken");
      return false;
    } else {
      return true;
    }
  }
}

export default checkToken;
