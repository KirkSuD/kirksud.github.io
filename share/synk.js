class SynkClient {
    constructor(server, quota, localStorageKey, expire=300_000) {
        this.server = server
        this.quota = quota
        this.localStorageKey = localStorageKey
        this.expire = expire
        this.load()
    }
    async request(pathname, data) {
        try {
            const resp = await fetch(this.server + pathname, {
                method: "POST",
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(data)
            })
            const res = await resp.json()
            return [res, res.error ?? null]
        } catch (e) {
            console.log("fetch error:", pathname, data, e)
            return [{error: "NetworkServerError"}, "NetworkServerError"]
        }
    }

    load() {
        let data = localStorage.getItem(this.localStorageKey)
        if (data !== null)
            data = JSON.parse(data)
        data = data ?? {
            id: null,
            token: null,
            key: null,
            device: null,
            time: null
        }
        this.id = data.id
        this.token = data.token
        this.key = data.key
        this.device = data.device
        this.time = data.time
    }
    save() {
        localStorage.setItem(this.localStorageKey, JSON.stringify({
            id: this.id,
            token: this.token,
            key: this.key,
            device: this.device,
            time: this.time
        }))
    }
    clear() {
        localStorage.removeItem(this.localStorageKey)
        this.load()
    }

    toB64(arr) {
        let binary = ""
        const bytes = new Uint8Array(arr)
        for (let i = 0; i < bytes.byteLength; i++)
            binary += String.fromCharCode(bytes[i])
        return window.btoa(binary)
    }
    toArr(b64) {
        const binaryString = atob(b64)
        const bytes = new Uint8Array(binaryString.length)
        for (let i = 0; i < binaryString.length; i++)
            bytes[i] = binaryString.charCodeAt(i)
        return bytes.buffer
    }
    async encrypt(data) {
        data = new TextEncoder().encode(data)
        const iv = new Uint8Array(12)
        crypto.getRandomValues(iv)
        const cipherData = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
                tagLength: 128
            },
            await crypto.subtle.importKey(
                "raw", this.toArr(this.key), {name: "AES-GCM"}, true, ["encrypt", "decrypt"]),
            data
        )
        const res = new Uint8Array(iv.byteLength + cipherData.byteLength)
        res.set(new Uint8Array(iv), 0)
        res.set(new Uint8Array(cipherData), iv.byteLength)
        return this.toB64(res.buffer)
    }
    async decrypt(data) {
        data = new Uint8Array(this.toArr(data))
        const iv = data.slice(0, 12)
        data = data.slice(12)
        return new TextDecoder().decode(await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
                tagLength: 128
            },
            await crypto.subtle.importKey(
                "raw", this.toArr(this.key), {name: "AES-GCM"}, true, ["encrypt", "decrypt"]),
            data
        ))
    }
    async hash(data, algo="SHA-256") {
        const hashArr = await crypto.subtle.digest(algo, new TextEncoder().encode(data))
        return Array.from(new Uint8Array(hashArr))
            .map(n => n.toString(16).padStart(2, "0")).join("")
    }

    async signup(data) {
        this.key = this.toB64(await crypto.subtle.exportKey("raw", await crypto.subtle.generateKey(
            {name: "AES-GCM", length: 128}, true, ["encrypt", "decrypt"])))
        const hash = await this.hash(data)
        data = await this.encrypt(data)
        const [res, err] = await this.request("/synk/signup", {quota: this.quota, hash, data})
        if (err === null) {
            this.id = res.id
            this.token = res.token
            res.time *= 1000
            this.time = res.time
            this.device = res.device
            this.save()
        }
        return [err === null, err]
    }
    async loginBegin() {
        const tzOffset = new Date().getTimezoneOffset() * 60_000
        const deadline = new Date(Date.now() - tzOffset + this.expire).toISOString()
        const [res, err] = await this.request("/synk/login", {
            id: this.id, token: this.token, key: this.key, deadline: deadline
        })
        return [res.code ?? null, err]
    }
    async loginCode(code) {
        const [res, err] = await this.request(`/synk/login/${code}`, {})
        return [res.verify ?? null, err]
    }
    async loginVerify(code, verify) {
        const [res, err] = await this.request(`/synk/login/${code}/${verify}`, {})
        return [err === null, err]
    }
    async loginEnd(code, verify) {
        const [res, err] = await this.request(`/synk/login/${code}/${verify}/end`, {})
        if (err === null) {
            this.id = res.id
            this.token = res.token
            this.key = res.key
            this.device = res.device
            this.save()
        }
        return [err === null, err]
    }
    async sync(data, force="") {
        const hash = await this.hash(data)
        const encrypted = await this.encrypt(data)
        const [res, err] = await this.request("/synk/sync", {
            id: this.id, token: this.token,
            hash, data: encrypted, device: this.device, force
        })
        if (err === null) {
            res.time *= 1000
            res.data = await this.decrypt(res.data)
        }
        if (err === null && res.result !== "conflict") {
            this.time = res.time
            this.save()
        }
        return [res, err]
    }
    async logout() {
        const [res, err] = await this.request("/synk/logout", {
            id: this.id, token: this.token, device: this.device})
        if (err === null)
            this.clear()
        return [err === null, err]
    }
    async delete() {
        const [res, err] = await this.request("/synk/delete", {
            id: this.id, token: this.token})
        if (err === null)
            this.clear()
        return [err === null, err]
    }
}

class Synk {
    constructor(
        server, quota, localStorageKey, expire=300_000,
        style=null, dialogTimeout=5_000,
    ) {
        this.client = new SynkClient(server, quota, localStorageKey, expire)
        this.dialogTimeout = dialogTimeout
        this.nextRun = 0
        this.running = 0

        style = style ?? `
<style>
#synk_dialog {
    position: fixed;
    right: 0;
    bottom: 0;

    margin: 10px;
    padding: 10px;

    background: white;
    border: 1px solid black;
    border-radius: 10px;

    user-select: none;
    cursor: pointer;
}
#synk_dialog > p {
    margin: 0;
    padding: 10px;
}
#synk_dialog > hr {
    margin: 0;
}

#synk_modal {
    position: fixed;
    top: 0;
    bottom: 0;
    left: 0;
    right: 0;

    margin: 10px;
    padding: 10px;

    background: white;
    border: 1px solid black;
    border-radius: 10px;

    display: flex;
    flex-direction: column;
}
#synk_modal > * {
    margin: 10px;
}
#synk_modal > p {
    white-space: pre-line;
}
#synk_modal > p > strong {
    display: block;
    margin: 15px;
    text-align: center;
    font-size: x-large;
}
#synk_modal > input, #synk_modal > button {
    padding: 10px 0;
}
</style>
        `
        document.head.insertAdjacentHTML("beforeend", style)
    }

    $(selectors, element=document) {
        return element.querySelector(selectors)
    }
    $$(selectors, element=document) {
        return element.querySelectorAll(selectors)
    }
    newElement(html) {
        const template = document.createElement("template")
        template.innerHTML = html
        return template.content.children[0]
    }

    removeDialogModal(callback=null) {
        const dialog = this.$("#synk_dialog")
        if (dialog !== null)
            dialog.remove()
        const modal = this.$("#synk_modal")
        if (modal !== null)
            modal.remove()
        if (callback !== null)
            callback(null)
    }
    showDialog(title, text, click=null, callback=null, timeout=0) {
        this.removeDialogModal()
        const dialog = this.newElement(`
            <div id="synk_dialog">
                <p>${title}</p>
                <hr>
                <p>${text}</p>
            </div>
        `)

        let timeoutId = null
        if (timeout === 0)
            timeout = this.dialogTimeout
        if (timeout !== null)
            timeoutId = setTimeout(() => {
                dialog.remove()
                if (callback !== null)
                    callback(null)
            }, timeout)

        if (click === null)
            click = () => dialog.remove()
        dialog.onclick = () => {
            if (timeoutId !== null)
                clearTimeout(timeoutId)
            click()
        }
        document.body.insertAdjacentElement("beforeend", dialog)
    }
    showModal(title, text, input, buttons) {
        this.removeDialogModal()
        const modal = this.newElement(`
            <div id="synk_modal">
                <p>${title}</p>
                <hr>
                <p>${text}</p>
            </div>
        `)
        if (input)
            modal.insertAdjacentHTML(
                "beforeend", `<input id="synk_input" type="text">`)
        for (const [text, click] of buttons) {
            const button = this.newElement(`<button>${text}</button>`)
            button.onclick = click
            modal.insertAdjacentElement("beforeend", button)
        }
        document.body.insertAdjacentElement("beforeend", modal)

    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms))
    }
    async waitRun(ms=10) {
        const thisRun = this.nextRun++
        while (this.running < thisRun)
            await this.sleep(ms)
    }

    async run(data, callback) {
        await this.waitRun()
        const cb = ((self, callback) => function(...args) {
            self.running++
            callback(...args)
        })(this, callback)
        if (this.client.id === null)
            this.showDialog(
                "Synk", "Click to sync", () => this.modalSignup(data, cb), cb)
        else
            await this.sync(data, "", cb)
    }
    async sync(data, force, callback) {
        this.showDialog("Synk", "Syncing...", () => {})
        const [res, err] = await this.client.sync(data, force)
        if (res.result === "conflict")
            return this.modalConflict(data, res, callback)
        if (err === "InvalidCredentials") {
            this.client.clear()
            return this.modalError(err, null, () => this.modalSignup(data, callback))
        }
        if (err)
            return this.modalError(err, callback)
        this.showDialog("Synk", "Synced", () => this.modalManage())
        callback(res.data ?? data)
    }
    modalError(err, callback=null, click=null) {
        this.showModal(
            `Error: ${err}`,
            {
                NetworkServerError: "Network or server error. Try again later.",
                InvalidArgs: "This client sends some invalid data to server.",
                InvalidCredentials: "You're logged out. Please re-login.",
                InvalidCode: "Invalid or expired code.",
                OutOfQuota: "Quota exceeded. Remove some data & try again.",
                OutOfStorage: "Sorry. Server is full.",
                TooManyDevices: "You've synced too many devices.",
                ServerLocked: "Server is locked. Ask server admin to unlock.",
            }[err] ?? "Unexpected error occurred.",
            false, [
            ["OK", () => this.removeDialogModal(click)]
        ])
        if (callback !== null)
            callback(null)
    }
    modalConflict(data, res, callback) {
        this.showModal(
            "Data conflict",
            `Both local & server data have changed since last sync.

            Local last sync: ${new Date(this.client.time).toLocaleString()}
            Server last sync: ${new Date(res.time).toLocaleString()}
            Now: ${new Date().toLocaleString()}

            Which one do you prefer?`,
            false, [
            ["Local", () => this.sync(data, "client", callback)],
            ["Server", () => this.sync(data, "server", callback)],
            ["Do nothing", () => this.removeDialogModal(callback)],
        ])
    }

    modalSignup(data, callback) {
        this.showModal(
            "Sync data using Synk",
            `No account is required.
            Data is encrypted before transmission.
            Server: ${this.client.server}`,
            false, [
            ["New device", async () => {
                const [success, err] = await this.client.signup(data)
                if (err)
                    this.modalError(err, callback)
                else {
                    this.showDialog("Synk", "Synced", () => this.modalManage())
                    callback(null)
                }
            }],
            ["Sync with old", async () => this.modalLoginCode(data, callback)],
            ["No / Later", () => this.removeDialogModal(callback)],
        ])
    }
    modalLoginCode(data, callback) {
        this.showModal(
            "Sync with old device",
            "Enter sync code:",
            true, [
            ["Continue", async () => {
                const code = this.$("#synk_input").value
                const [verify, err] = await this.client.loginCode(code)
                if (err === "InvalidCredentials")
                    this.modalError(err, null, () => this.modalLoginCode(data, callback))
                else if (err)
                    this.modalError(err, callback)
                else
                    this.modalLoginEnd(data, code, verify, callback)
            }],
            ["Cancel", () => this.removeDialogModal(callback)]
        ])
    }
    modalLoginEnd(data, code, verify, callback) {
        this.showModal(
            "Sync with old device",
            `Verify code:
            <strong>${verify}</strong>`,
            false, [
            ["Continue", async () => {
                const [success, err] = await this.client.loginEnd(code, verify)
                if (err)
                    this.modalError(err, callback)
                else {
                    this.removeDialogModal()
                    this.sync(data, "", callback)
                }
            }],
            ["Cancel", () => this.removeDialogModal(callback)]
        ])
    }

    async modalManage() {
        await this.waitRun()
        const callback = () => this.running++
        this.showModal(
            "Manage Synk",
            `ID: ${this.client.id}
            Device: ${this.client.device}
            Last sync: ${new Date(this.client.time).toLocaleString()}`,
            false, [
            ["Sync with new", async () => {
                const [code, err] = await this.client.loginBegin()
                if (err)
                    this.modalError(err, callback)
                else
                    this.modalLoginBegin(code, callback)
            }],
            ["Log out", async () => {
                const [success, err] = await this.client.logout()
                if (err)
                    this.modalError(err, callback)
                else {
                    this.showDialog("Synk", "Logged out")
                    callback(null)
                }
            }],
            // ["Log out locally", async () => {
            //     this.client.clear()
            //     this.showDialog("Synk", "Logged out locally")
            //     callback(null)
            // }],
            ["Delete account", async () => {
                const [success, err] = await this.client.delete()
                if (err)
                    this.modalError(err, callback)
                else {
                    this.showDialog("Synk", "Deleted account")
                    callback(null)
                }
            }],
            ["Do nothing", () => this.removeDialogModal(callback)],
        ])
    }
    modalLoginBegin(code, callback) {
        this.showModal(
            "Sync with new device",
            `Sync code:
            <strong>${code}</strong>`,
            false, [
            ["Continue", async () => this.modalLoginVerify(code, callback)],
            ["Cancel", () => this.removeDialogModal(callback)]
        ])
    }
    modalLoginVerify(code, callback) {
        this.showModal(
            "Sync with new device",
            "Enter verify code:",
            true, [
            ["Continue", async () => {
                const verify = this.$("#synk_input").value
                const [success, err] = await this.client.loginVerify(code, verify)
                if (err === "InvalidCredentials")
                    this.modalError(err, null, () => this.modalLoginVerify(code, callback))
                else if (err)
                    this.modalError(err, callback)
                else {
                    this.showDialog("Synk", "New device ready")
                    callback(null)
                }
            }],
            ["Cancel", () => this.removeDialogModal(callback)]
        ])
    }
}
