module.exports = function(RED) {
    "use strict";
    const fetch = require('node-fetch');
    const https = require('https');

    function NtfyUpdateNode(config) {
        RED.nodes.createNode(this, config);
        this.name = config.name;
        this.serverConfigNode = RED.nodes.getNode(config.serverConfig);
        this.command = config.command;
        this.topic = config.topic;
        this.sequenceId = config.sequenceId;

        let node = this;

        if (!node.serverConfigNode || !node.serverConfigNode.server) {
            node.error("Ntfy server configuration is missing or incomplete.");
            node.status({fill:"red", shape:"ring", text:"config error"});
            return;
        }

        const ntfyServerBaseUrl = node.serverConfigNode.server;

        node.on('input', async function(msg, send, done) {
            const command = (msg.command || node.command || "clear").toLowerCase();
            const topic = msg.topic || node.topic;
            const sequenceId = msg["sequence-id"] || node.sequenceId;

            if (!topic) {
                node.error("Topic not configured or provided in msg.topic", msg);
                node.status({fill:"red", shape:"ring", text:"no topic"});
                if (done) { done(); }
                return;
            }

            if (!sequenceId) {
                node.error("Sequence ID is required for update operations", msg);
                node.status({fill:"red", shape:"ring", text:"no sequenceId"});
                if (done) { done(); }
                return;
            }

            const headers = {};
            if (node.serverConfigNode.accessToken) {
                headers['Authorization'] = `Bearer ${node.serverConfigNode.accessToken}`;
            } else if (node.serverConfigNode.username && node.serverConfigNode.password) {
                const B64 = Buffer.from(`${node.serverConfigNode.username}:${node.serverConfigNode.password}`).toString('base64');
                headers['Authorization'] = `Basic ${B64}`;
            }
            headers['X-sequence-id'] = sequenceId;

            let method, url;
            if (command === "clear") {
                method = "PUT";
                url = `${ntfyServerBaseUrl}/${topic}/${sequenceId}/clear`;
            } else if (command === "delete") {
                method = "DELETE";
                url = `${ntfyServerBaseUrl}/${topic}/${sequenceId}`;
            } else {
                node.error("Invalid command. Must be 'clear' or 'delete'", msg);
                node.status({fill:"red", shape:"ring", text:"invalid command"});
                if (done) { done(); }
                return;
            }

            const fetchOptions = {
                method: method,
                headers: headers
            };

            if (url.startsWith('https://') && node.insecure) {
                fetchOptions.agent = new https.Agent({ rejectUnauthorized: false });
            }

            node.status({fill:"blue", shape:"dot", text:`${command}...`});

            try {
                const response = await fetch(url, fetchOptions);
                if (!response.ok) {
                    const errorBody = await response.text();
                    node.error(`Ntfy API error: ${response.status} ${response.statusText} - ${errorBody}`, msg);
                    node.status({fill:"red", shape:"ring", text:`API error ${response.status}`});
                } else {
                    node.status({fill:"green", shape:"dot", text:`${command} sent`});
                }
            } catch (err) {
                node.error(`Failed to send Ntfy update: ${err.message}`, msg);
                node.status({fill:"red", shape:"ring", text:"send error"});
            }
            if (done) { done(); }
        });

        node.on('close', function() {
            node.status({});
        });
    }
    RED.nodes.registerType("ntfy-update", NtfyUpdateNode);
}
