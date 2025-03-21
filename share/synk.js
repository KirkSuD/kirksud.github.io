class SynkCrypto {
    async hash(data, algo="SHA-256") {
        const hashArr = await crypto.subtle.digest(algo, new TextEncoder().encode(data))
        return Array.from(new Uint8Array(hashArr))
            .map(n => n.toString(16).padStart(2, "0")).join("")
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

    async newAesKey() {
        const key = await crypto.subtle.generateKey(
            {name: "AES-GCM", length: 128}, true, ["encrypt", "decrypt"])
        return this.toB64(await crypto.subtle.exportKey("raw", key))
    }
    async importAesKey(key) {
        return await crypto.subtle.importKey(
            "raw", this.toArr(key), {name: "AES-GCM"}, true, ["encrypt", "decrypt"])
    }
    async encryptAes(data, key) {
        const iv = new Uint8Array(12)
        crypto.getRandomValues(iv)
        const algo = {name: "AES-GCM", iv: iv, tagLength: 128}
        key = await this.importAesKey(key)
        data = new TextEncoder().encode(data)

        const cipherData = await crypto.subtle.encrypt(algo, key, data)
        const res = new Uint8Array(iv.byteLength + cipherData.byteLength)
        res.set(new Uint8Array(iv), 0)
        res.set(new Uint8Array(cipherData), iv.byteLength)
        return this.toB64(res.buffer)
    }
    async decryptAes(data, key) {
        data = new Uint8Array(this.toArr(data))
        const iv = data.slice(0, 12)
        const algo = {name: "AES-GCM", iv: iv, tagLength: 128}
        key = await this.importAesKey(key)
        data = data.slice(12)

        const plainData = await crypto.subtle.decrypt(algo, key, data)
        return new TextDecoder().decode(plainData)
    }

    async newRsaKey() {
        const algo = {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        }
        const key = await crypto.subtle.generateKey(algo, true, ["encrypt", "decrypt"])
        return [
            JSON.stringify(await crypto.subtle.exportKey("jwk", key.publicKey)),
            JSON.stringify(await crypto.subtle.exportKey("jwk", key.privateKey))
        ]
    }
    async importRsaKey(key, usage="encrypt") {
        const algo = {name: "RSA-OAEP", hash: "SHA-256"}
        return await crypto.subtle.importKey(
            "jwk", JSON.parse(key), algo, true, [usage])
    }
    async encryptRsa(data, key) {
        const algo = {name: "RSA-OAEP"}
        key = await this.importRsaKey(key, "encrypt")
        data = new TextEncoder().encode(data)
        const cipherData = await crypto.subtle.encrypt(algo, key, data)
        return this.toB64(new Uint8Array(cipherData))
    }
    async decryptRsa(data, key) {
        const algo = {name: "RSA-OAEP"}
        key = await this.importRsaKey(key, "decrypt")
        data = new Uint8Array(this.toArr(data))

        const plainData = await crypto.subtle.decrypt(algo, key, data)
        return new TextDecoder().decode(plainData)
    }
}

class SynkClient {
    constructor(server, quota, localStorageKey, expire=300_000) {
        this.crypto = new SynkCrypto()
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
            if (!resp.ok)
                throw new Error(`Response not ok: ${resp.status} ${resp.statusText}`)
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

    async signup(data) {
        this.key = await this.crypto.newAesKey()
        const hash = await this.crypto.hash(data)
        data = await this.crypto.encryptAes(data, this.key)
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
    async loginSetPubkey() {
        const keyPair = await this.crypto.newRsaKey()
        const deadline = new Date(Date.now() + this.expire).toISOString()
        const [res, err] = await this.request("/synk/login", {
            pubkey: keyPair[0], deadline
        })
        return [[res.code ?? null, keyPair[1]], err]
    }
    async loginGetPubkey(code) {
        const [res, err] = await this.request(`/synk/login/${code}`, {
            id: this.id, token: this.token})
        return [[res.verify ?? null, res.pubkey ?? null], err]
    }
    async loginSetKey(code, verify, pubkey) {
        const [res, err] = await this.request(`/synk/login/${code}/${verify}`, {
            token: await this.crypto.encryptRsa(this.token, pubkey),
            key: await this.crypto.encryptRsa(this.key, pubkey)
        })
        return [err === null, err]
    }
    async loginGetKey(code, verify, privkey) {
        const [res, err] = await this.request(`/synk/login/${code}/${verify}/end`, {})
        if (err === null) {
            this.id = res.id
            this.token = await this.crypto.decryptRsa(res.token, privkey)
            this.key = await this.crypto.decryptRsa(res.key, privkey)
            this.device = res.device
            this.save()
        }
        return [err === null, err]
    }
    async sync(data, force="") {
        const hash = await this.crypto.hash(data)
        data = await this.crypto.encryptAes(data, this.key)
        const [res, err] = await this.request("/synk/sync", {
            id: this.id, token: this.token,
            hash, data, device: this.device, force
        })
        if (err === null) {
            res.time *= 1000
            res.data = await this.crypto.decryptAes(res.data, this.key)
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
        server, quota, localStorageKey,
        exportFilePrefix="export", syncCallback=null,
        expire=300_000, dialogTimeout=5_000,
        style=null, i18n=null,
    ) {
        this.client = new SynkClient(server, quota, localStorageKey + "_synk", expire)
        this.localStorageKey = localStorageKey
        this.exportFilePrefix = exportFilePrefix
        this.syncCallback = syncCallback ?? (() => {})
        this.dialogTimeout = dialogTimeout

        this.nextRun = 0
        this.running = 0
        this.shownSignupDialog = false

        style = style ?? `
<style>
#synk_dialog {
    position: fixed;
    right: 0;
    bottom: 0;

    margin: 0.63em;
    padding: 0.63em;

    background: white;
    border: thin solid black;
    border-radius: 0.63em;

    user-select: none;
    cursor: pointer;
}
#synk_dialog > p {
    margin: 0;
    padding: 0.63em;
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

    margin: 0.63em;
    padding: 0.63em;

    background: white;
    border: thin solid black;
    border-radius: 0.63em;

    display: flex;
    flex-direction: column;
}
#synk_modal > * {
    margin: 0.63em;
}
#synk_modal > p {
    white-space: pre-line;
}
#synk_modal > p > strong {
    display: block;
    margin: 0.95em;
    text-align: center;
    font-size: x-large;
}
#synk_modal > input, #synk_modal > button {
    padding: 0.63em;
}

#synk_modal > #synk_file_button {
    padding: 0;
}
#synk_file_button label {
    display: inline-block;
    width: 100%;
    height: 100%;
    padding: 0.63em;
    margin: 0;
    box-sizing: border-box;
}
#synk_file_button input {
    display: none;
}
</style>
        `
        document.head.insertAdjacentHTML("beforeend", style)

        i18n = i18n ?? {
            "en-US": {
                synk: "Synk",
                clickToSync: "Click to sync",
                syncing: "Syncing...",
                networkServerErrorShort: "Network/Server Error!",
                synced: "Synced",
                errorIs: "Error: ",
                ok: "OK",

                NetworkServerError: "Network or server error. Try again later.",
                InvalidArgs: "This client sends some invalid data to server.",
                InvalidCredentials: "You're logged out. Please re-login.",
                InvalidCode: "Invalid or expired code.",
                OutOfQuota: "Quota exceeded. Remove some data & try again.",
                OutOfStorage: "Sorry. Server is full.",
                TooManyDevices: "You've synced too many devices.",
                ServerLocked: "Server is locked. Ask server admin to unlock.",
                UnexpectedError: "Unexpected error occurred.",

                dataConflict: "Data conflict",
                bothLocalServerDataChanged: "Both local & server data have changed since last sync.",
                localLastSync: "Local last sync: ",
                serverLastSync: "Server last sync: ",
                currentTime: "Current time: ",
                whichOneToKeep: "Which one to keep?",

                local: "Local",
                server: "Server",
                doNothing: "Do nothing",

                syncDataUsingSynk: "Sync data using Synk",
                noAccountIsRequired: "No account is required.",
                usingE2EE: "Using end-to-end encryption.",
                serverIs: "Server: ",

                signup: "Sign up",
                login: "Log in",
                importData: "Import data",
                exportData: "Export data",
                clearData: "Clear data",
                clearDataConfirm: "Confirm to clear all data?",

                enterSyncCode: "Enter sync code:",
                continue: "Continue",
                cancel: "Cancel",

                verifyCode: "Verify code:",
                manageSynk: "Manage Synk",
                idIs: "ID: ",
                deviceIs: "Device: ",
                lastSync: "Last sync: ",

                logout: "Log out",
                loggedOut: "Logged out",
                logoutLocally: "Log out locally",
                loggedOutLocally: "Logged out locally",
                deleteAccount: "Delete account",
                deletedAccount: "Deleted account",

                loginOnAnotherDevice: "Log in on another device",
                syncCode: "Sync code:",
                enterVerifyCode: "Enter verify code:",
            },

            "zh-TW": {
                synk: "Synk 同步",
                clickToSync: "點此開始同步",
                syncing: "同步中…",
                networkServerErrorShort: "網路或伺服器錯誤！",
                synced: "同步成功",
                errorIs: "錯誤：",
                ok: "OK",

                NetworkServerError: "網路或伺服器錯誤，請稍後重試。",
                InvalidArgs: "此用戶端不知為何發送了伺服器不接受的資料。",
                InvalidCredentials: "您已被登出，請重新登入。",
                InvalidCode: "錯誤或已過期的驗證碼。",
                OutOfQuota: "儲存空間配額已用完，請刪除一些資料再重試。",
                OutOfStorage: "抱歉，伺服器已滿。",
                TooManyDevices: "你同步了過多的裝置。",
                ServerLocked: "伺服器已鎖定，請向管理員要求解鎖。",
                UnexpectedError: "發生了未知的錯誤。",

                dataConflict: "同步資料衝突",
                bothLocalServerDataChanged: "本地和伺服器的資料在上次同步後都有變更。",
                localLastSync: "本地資料上次同步：",
                serverLastSync: "伺服器資料上次同步：",
                currentTime: "現在時間：",
                whichOneToKeep: "保留哪一份資料？",

                local: "本地",
                server: "伺服器",
                doNothing: "不做任何事",

                syncDataUsingSynk: "使用 Synk 同步資料",
                noAccountIsRequired: "不需要帳號。",
                usingE2EE: "使用端對端加密。",
                serverIs: "伺服器：",

                signup: "註冊",
                login: "登入",
                importData: "匯入資料",
                exportData: "匯出資料",
                clearData: "清除資料",
                clearDataConfirm: "確認清除所有資料？",

                enterSyncCode: "輸入同步碼：",
                continue: "繼續",
                cancel: "取消",

                verifyCode: "驗證碼：",
                manageSynk: "管理 Synk",
                idIs: "編號：",
                deviceIs: "裝置：",
                lastSync: "上次同步：",

                logout: "登出",
                loggedOut: "已登出",
                logoutLocally: "刪除本地帳號資料",
                loggedOutLocally: "已刪除本地帳號資料",
                deleteAccount: "刪除帳號",
                deletedAccount: "已刪除帳號",

                loginOnAnotherDevice: "登入另一個裝置",
                syncCode: "同步碼：",
                enterVerifyCode: "輸入驗證碼：",
            },

            "en": "en-US",
            "zh": "zh-TW",
        }
        for (const lang in i18n)
            if (typeof i18n[lang] === "string" && i18n[lang] in i18n)
                i18n[lang] = i18n[i18n[lang]]

        this.i18n = i18n["en"]
        for (const lang of navigator.languages)
            if (lang in i18n) {
                this.i18n = i18n[lang]
                break
            }
    }

    $(selectors, element=document) {
        return element.querySelector(selectors)
    }
    $$(selectors, element=document) {
        return Array.from(element.querySelectorAll(selectors))
    }
    $html(html) {
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
        const dialog = this.$html(`
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
        const modal = this.$html(`
            <div id="synk_modal">
                <p>${title}</p>
                <hr>
                <p>${text}</p>
            </div>
        `)
        if (input) {
            const input = this.$html(`<input id="synk_input" type="text">`)
            if (buttons.length)
                input.onkeydown = evt => {
                    if (evt.key === "Enter")
                        buttons[0][1]()
                }
            modal.insertAdjacentElement("beforeend", input)
        }
        for (const [text, click] of buttons) {
            let button
            if (text === "importData") {
                button = this.$html(`
                    <button id="synk_file_button">
                        <label>
                            ${this.i18n[text]}
                            <input type="file" accept=".json,.txt">
                        </label>
                    </button>`)
                this.$("input", button).onchange = click
            }
            else {
                button = this.$html(`<button>${text}</button>`)
                button.onclick = click
            }
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

    async run(callback=null) {
        const data = localStorage.getItem(this.localStorageKey) ?? "null"
        callback = callback ?? this.syncCallback

        await this.waitRun()
        const cb = syncData => {
            this.running++
            if (syncData === null || syncData === data)
                return
            localStorage.setItem(this.localStorageKey, syncData)
            callback(syncData)
        }

        if (this.client.id !== null) {
            await this.sync(data, "", cb)
            return
        }
        if (this.shownSignupDialog) {
            cb(null)
            return
        }
        this.shownSignupDialog = true
        this.showDialog(
            this.i18n.synk, this.i18n.clickToSync, () => this.modalSignup(data, cb), cb)
    }
    async sync(data, force, callback) {
        this.showDialog(this.i18n.synk, this.i18n.syncing, () => {})
        const [res, err] = await this.client.sync(data, force)
        if (err === null && res.result === "conflict")
            return this.modalConflict(data, res, callback)
        if (err === "InvalidCredentials") {
            this.client.clear()
            return this.modalError(err, null, () => this.modalSignup(data, callback))
        }
        if (err === "NetworkServerError") {
            this.showDialog(this.i18n.synk, this.i18n.networkServerErrorShort)
            callback(null)
            return
        }
        if (err)
            return this.modalError(err, callback)
        this.showDialog(this.i18n.synk, this.i18n.synced, () => this.modalManage())
        callback(res.data ?? data)
    }
    modalError(err, callback=null, click=null) {
        this.showModal(
            `${this.i18n.errorIs}${err}`,
            this.i18n[err] ?? this.i18n.UnexpectedError,
            false, [
            [this.i18n.ok, () => this.removeDialogModal(click)]
        ])
        if (callback !== null)
            callback(null)
    }
    modalConflict(data, res, callback) {
        this.showModal(
            this.i18n.dataConflict,
            `${this.i18n.bothLocalServerDataChanged}

            ${this.i18n.localLastSync}${new Date(this.client.time).toLocaleString()}
            ${this.i18n.serverLastSync}${new Date(res.time).toLocaleString()}
            ${this.i18n.currentTime}${new Date().toLocaleString()}

            ${this.i18n.whichOneToKeep}`,
            false, [
            [this.i18n.local, () => this.sync(data, "client", callback)],
            [this.i18n.server, () => this.sync(data, "server", callback)],
            ["importData", () => this.importData(callback)],
            [this.i18n.exportData, () => this.exportData(callback)],
            [this.i18n.clearData, () => this.clearData(callback)],
            [this.i18n.doNothing, () => this.removeDialogModal(callback)],
        ])
    }

    modalSignup(data, callback) {
        this.showModal(
            this.i18n.syncDataUsingSynk,
            `${this.i18n.noAccountIsRequired}
            ${this.i18n.usingE2EE}
            ${this.i18n.serverIs}${this.client.server}`,
            false, [
            [this.i18n.signup, async () => {
                const [success, err] = await this.client.signup(data)
                if (err)
                    this.modalError(err, callback)
                else {
                    this.showDialog(this.i18n.synk, this.i18n.synced, () => this.modalManage())
                    callback(null)
                }
            }],
            [this.i18n.login, async () => {
                const [[code, privkey], err] = await this.client.loginSetPubkey()
                if (err)
                    this.modalError(err, callback)
                else
                    this.modalLoginSetPubkey(data, code, privkey, callback)
            }],
            ["importData", () => this.importData(callback)],
            [this.i18n.exportData, () => this.exportData(callback)],
            [this.i18n.clearData, () => this.clearData(callback)],
            [this.i18n.doNothing, () => this.removeDialogModal(callback)],
        ])
    }
    modalLoginSetPubkey(data, code, privkey, callback) {
        this.showModal(
            this.i18n.login,
            `${this.i18n.syncCode}
            <strong>${code}</strong>`,
            false, [
            [this.i18n.continue, () => this.modalLoginGetKey(data, code, privkey, callback)],
            [this.i18n.cancel, () => this.removeDialogModal(callback)]
        ])
    }
    modalLoginGetKey(data, code, privkey, callback) {
        this.showModal(
            this.i18n.login,
            this.i18n.enterVerifyCode,
            true, [
            [this.i18n.continue, async () => {
                const verify = this.$("#synk_input").value
                const [success, err] = await this.client.loginGetKey(code, verify, privkey)
                if (err === "InvalidCode")
                    this.modalLoginGetKey(data, code, privkey, callback)
                else if (err)
                    this.modalError(err, callback)
                else {
                    this.removeDialogModal()
                    this.sync(data, "", callback)
                }
            }],
            [this.i18n.cancel, () => this.removeDialogModal(callback)]
        ])
    }

    async modalManage() {
        await this.waitRun()
        const callback = () => this.running++
        this.showModal(
            this.i18n.manageSynk,
            `${this.i18n.serverIs}${this.client.server}
            ${this.i18n.idIs}${this.client.id}
            ${this.i18n.deviceIs}${this.client.device}
            ${this.i18n.lastSync}${new Date(this.client.time).toLocaleString()}`,
            false, [
            [this.i18n.loginOnAnotherDevice, () => this.modalLoginGetPubkey(callback)],
            [this.i18n.logout, async () => {
                const [success, err] = await this.client.logout()
                if (err)
                    this.modalError(err, callback)
                else {
                    this.showDialog(this.i18n.synk, this.i18n.loggedOut)
                    callback(null)
                }
            }],
            // [this.i18n.logoutLocally, async () => {
            //     this.client.clear()
            //     this.showDialog(this.i18n.synk, this.i18n.loggedOutLocally)
            //     callback(null)
            // }],
            [this.i18n.deleteAccount, async () => {
                const [success, err] = await this.client.delete()
                if (err)
                    this.modalError(err, callback)
                else {
                    this.showDialog(this.i18n.synk, this.i18n.deletedAccount)
                    callback(null)
                }
            }],
            ["importData", () => this.importData(callback)],
            [this.i18n.exportData, () => this.exportData(callback)],
            [this.i18n.clearData, () => this.clearData(callback)],
            [this.i18n.doNothing, () => this.removeDialogModal(callback)],
        ])
    }
    modalLoginGetPubkey(callback) {
        this.showModal(
            this.i18n.loginOnAnotherDevice,
            this.i18n.enterSyncCode,
            true, [
            [this.i18n.continue, async () => {
                const code = this.$("#synk_input").value
                let verify, pubkey, success, err
                [[verify, pubkey], err] = await this.client.loginGetPubkey(code)
                if (err === "InvalidCode")
                    return this.modalLoginGetPubkey(callback)
                if (err)
                    return this.modalError(err, callback);
                [success, err] = await this.client.loginSetKey(code, verify, pubkey)
                if (err)
                    return this.modalError(err, callback)
                this.modalLoginSetKey(verify, callback)
            }],
            [this.i18n.cancel, () => this.removeDialogModal(callback)]
        ])
    }
    modalLoginSetKey(verify, callback) {
        this.showModal(
            this.i18n.loginOnAnotherDevice,
            `${this.i18n.verifyCode}
            <strong>${verify}</strong>`,
            false, [
            [this.i18n.ok, () => this.removeDialogModal(callback)]
        ])
    }

    importData(callback) {
        const file = this.$("#synk_file_button input").files[0]
        const file_reader = new FileReader()
        file_reader.onload = event => {
            // save to storage, call app callback to show new data, run sync
            const data = event.target.result
            localStorage.setItem(this.localStorageKey, data)
            this.syncCallback(data)
            this.run()
        }
        file_reader.readAsText(file)
        this.removeDialogModal(callback)
    }
    exportData(callback) {
        const pad2 = (n => ((n < 10) ? `0${n}` : `${n}`))
        const d = new Date()
        const timestamp = `${d.getFullYear()}${pad2(d.getMonth()+1)}${pad2(d.getDate())}` +
            `_${pad2(d.getHours())}${pad2(d.getMinutes())}${pad2(d.getSeconds())}`

        const text = localStorage.getItem(this.localStorageKey)
        const file = new Blob([text], {type: "application/json"})
        const fileUrl = URL.createObjectURL(file)
        const fileName = `${this.exportFilePrefix}_${timestamp}.json`

        const exportLink = this.$html(`<a href=${fileUrl} download=${fileName}></a>`)
        document.body.insertAdjacentElement("beforeend", exportLink)
        exportLink.click()
        exportLink.remove()
        this.removeDialogModal(callback)
    }
    clearData(callback) {
        // remove from storage, call app callback to show, run sync
        if (!confirm(this.i18n.clearDataConfirm))
            return
        localStorage.removeItem(this.localStorageKey)
        this.syncCallback("null")
        this.run()
        this.removeDialogModal(callback)
    }
}
