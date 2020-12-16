import store from "store"

export function isLoggedIn() {
    return !!store.get("loggedIn");
}
