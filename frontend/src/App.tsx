import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Cases from "./pages/Cases";
import CaseDetails from "./pages/CaseDetails";
import Search from "./pages/Search";
import Graph from "./pages/Graph";
import Timeline from "./pages/Timeline";
import Alerts from "./pages/Alerts";

function App() {
	return (
		<Router>
			<Routes>
				<Route path="/" element={<Layout />}>
					<Route index element={<Dashboard />} />
					<Route path="cases" element={<Cases />} />
					<Route path="cases/:caseId" element={<CaseDetails />} />
					<Route path="alerts" element={<Alerts />} />

					<Route path="search" element={<Search />} />
					<Route path="timeline" element={<Timeline />} />
					<Route path="graph" element={<Graph />} />
				</Route>
			</Routes>
		</Router>
	);
}

export default App;
