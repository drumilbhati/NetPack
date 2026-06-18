import React, { useState, useEffect } from "react";

const forensicPhrases = [
	"Decrypting packets",
	"Gathering anomalies",
	"Investigating leads",
	"Reconstructing TCP streams",
	"Analyzing payload signatures",
	"Filtering malicious traffic",
	"Parsing PCAP headers",
	"Scanning connection handshakes",
	"Tracing network routes",
	"Hashing evidence files",
	"Indexing packet sequences",
	"Running threat intelligence matchers"
];

interface LoaderProps {
	message?: string;
	fullscreen?: boolean;
	inline?: boolean;
}

export const Loader: React.FC<LoaderProps> = ({
	message,
	fullscreen = false,
	inline = false,
}) => {
	const [phraseIndex, setPhraseIndex] = useState(0);
	const [fade, setFade] = useState(true);

	useEffect(() => {
		// Only cycle phrases if we don't have a static message override
		if (message) return;

		const phraseInterval = setInterval(() => {
			setFade(false);
			setTimeout(() => {
				setPhraseIndex((prev) => (prev + 1) % forensicPhrases.length);
				setFade(true);
			}, 300); // Wait for fade-out to finish before changing text
		}, 2000);

		return () => clearInterval(phraseInterval);
	}, [message]);

	const containerStyle: React.CSSProperties = fullscreen
		? {
				display: "flex",
				height: "100vh",
				width: "100vw",
				position: "fixed",
				top: 0,
				left: 0,
				backgroundColor: "rgba(243, 244, 246, 0.95)",
				zIndex: 9999,
				alignItems: "center",
				justifyContent: "center",
				flexDirection: "column",
				gap: "1.5rem",
				backdropFilter: "blur(4px)",
		  }
		: inline
		? {
				display: "inline-flex",
				alignItems: "center",
				justifyContent: "center",
				gap: "0.5rem",
				color: "inherit",
		  }
		: {
				display: "flex",
				minHeight: "200px",
				alignItems: "center",
				justifyContent: "center",
				flexDirection: "column",
				gap: "1.5rem",
				color: "var(--text-secondary)",
				width: "100%",
				padding: "2rem",
		  };

	const currentPhrase = message || forensicPhrases[phraseIndex];

	return (
		<div style={containerStyle} className="forensic-loader-container">
			<div className={`spinner ${inline ? "spinner-inline" : "spinner-normal"}`}></div>
			{!inline && (
				<div
					className="forensic-loader-text"
					style={{
						fontSize: "1rem",
						fontWeight: 500,
						color: "var(--text-color)",
						textAlign: "center",
						minHeight: "1.5rem",
						opacity: fade ? 1 : 0,
						transition: "opacity 0.3s ease-in-out",
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
						gap: "0.5rem",
					}}
				>
					<span>{currentPhrase}</span>
					<span className="loading-dots">
						<span className="dot">.</span>
						<span className="dot">.</span>
						<span className="dot">.</span>
					</span>
				</div>
			)}
			{inline && (
				<span style={{ fontSize: "inherit", fontWeight: "inherit" }}>
					{currentPhrase}...
				</span>
			)}
		</div>
	);
};

export default Loader;
