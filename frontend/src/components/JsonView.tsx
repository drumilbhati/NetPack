import React from "react";

interface JsonViewProps {
	data: any;
	maxHeight?: string;
}

const JsonView: React.FC<JsonViewProps> = ({ data, maxHeight = "300px" }) => {
	const syntaxHighlight = (json: string) => {
		if (!json) return "";
		json = json
			.replace(/&/g, "&amp;")
			.replace(/</g, "&lt;")
			.replace(/>/g, "&gt;");
		return json.replace(
			/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
			(match) => {
				let cls = "json-number";
				if (/^"/.test(match)) {
					if (/:$/.test(match)) {
						cls = "json-key";
					} else {
						cls = "json-string";
					}
				} else if (/true|false/.test(match)) {
					cls = "json-boolean";
				} else if (/null/.test(match)) {
					cls = "json-null";
				}
				return `<span class="${cls}">${match}</span>`;
			},
		);
	};

	const jsonString = JSON.stringify(data, null, 2);
	const highlighted = syntaxHighlight(jsonString);

	return (
		<pre
			style={{
				background: "#1e293b",
				color: "#f8fafc",
				padding: "1rem",
				borderRadius: "0.5rem",
				fontSize: "0.8rem",
				overflow: "auto",
				maxHeight: maxHeight,
				whiteSpace: "pre-wrap",
				wordBreak: "break-all",
				margin: 0,
				lineHeight: 1.5,
				fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
			}}
			dangerouslySetInnerHTML={{ __html: highlighted }}
		/>
	);
};

export default JsonView;
