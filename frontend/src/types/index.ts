export interface Case {
	id: string;
	title: string;
	description?: string;
	created_at: string;
}

export interface SearchResult {
	case_id?: string;
	evidence_id?: string;
	sha256?: string;
	timestamp?: string;
	source_ip?: string;
	destination_ip?: string;
	source_port?: number;
	destination_port?: number;
	protocol?: string;
	http_url?: string;
	http_user_agent?: string;
	http_host?: string;
	tls_sni?: string;
	dns_query?: string;
	ftp_command?: string;
	smtp_command?: string;
	smb_command?: string;
	payload_signatures?: string[];
	bytes_sent?: number;
	bytes_received?: number;
	duration?: number;
	packet_count?: number;
	anomaly_score?: number;
	is_anomaly?: boolean;
	metadata: Record<string, unknown>;
}
