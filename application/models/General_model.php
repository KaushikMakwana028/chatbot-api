<?php defined('BASEPATH') or exit('No direct script access allowed');

class General_model extends CI_Model
{

    public function __construct()
    {
        parent::__construct();
        $this->load->database();
    }

    public function getOne($table, $where)
    {
        $query = $this->db->get_where($table, $where);
        return $query->row();
    }


    public function getAll($table, $where = '')
    {
        if (!empty($where)) {
            $this->db->where($where);
        }
        $query = $this->db->get($table);
        return $query->result();
    }

    public function insert($table, $data)
    {
        $this->db->insert($table, $data);
        return $this->db->insert_id();
    }

    public function update($table, $where, $data)
    {
        return $this->db->update($table, $data, $where);
    }
    public function getCount($table, $where = [], $isActive = null)
    {
        if (!is_null($isActive)) {
            $where['isActive'] = $isActive;
        }

        if (!empty($where)) {
            $query = $this->db->select()
                ->where($where)
                ->get($table);
        } else {
            $query = $this->db->select()
                ->get($table);
        }

        return $query->num_rows();
    }
    public function getData($table, $selectFields = '*', $where = [])
    {
        $this->db->select($selectFields);
        $this->db->from($table);
        if (!empty($where)) {
            $this->db->where($where);
        }
        $query = $this->db->get();
        return $query->result_array();
    }

    public function getCurrentMonthCustomers()
    {
        $query = $this->db->query("
            SELECT * FROM customers 
            WHERE MONTH(purchase_date) = MONTH(CURRENT_DATE()) 
            AND YEAR(purchase_date) = YEAR(CURRENT_DATE())
        ");

        return $query->result_array(); // Returns all matching records as an array
    }
    public function getCustomersAfter90Days()
    {
        $this->db->where('DATE(purchase_date) <=', date('Y-m-d', strtotime('-90 days')));
        $query = $this->db->get('customers');
        return $query->result();
    }
    public function get_all_categories($search = null)
    {
        if (!empty($search)) {
            $this->db->like('name', $search);
        }
        return $this->db->order_by('parent_id ASC, name ASC')
            ->get('categories')
            ->result();
    }
}


