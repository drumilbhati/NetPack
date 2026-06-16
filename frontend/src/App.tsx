import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Cases from './pages/Cases';
import Search from './pages/Search';
import Graph from './pages/Graph';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="cases" element={<Cases />} />
          <Route path="search" element={<Search />} />
          <Route path="graph" element={<Graph />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;
