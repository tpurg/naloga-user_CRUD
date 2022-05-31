export class User {
    id: number;
    userName: String;
    password: String;

    constructor(id:number, userName: String, password: String) {
        this.id = id;
        this.userName = userName;
        this.password = password;
    }
}
