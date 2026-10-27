"""Synthetic (fake) patient data so the demo contains no real PHI."""

HOSPITALS = {
    "chennai":   "Chennai General Hospital",
    "vellore":   "Vellore Medical Centre",
    "bengaluru": "Bengaluru Heart Institute",
    "delhi":     "Delhi Central Hospital",
}


def _p(pid, name, age, sex, blood, cond, allergy, meds, visit):
    return {"patient_id": pid, "name": name, "age": age, "sex": sex, "blood_group": blood,
            "conditions": cond, "allergies": allergy, "medications": meds, "last_visit": visit}


PATIENTS = {
    "chennai": [
        _p("P-1001", "Arjun Menon", 54, "M", "O+", ["Type 2 diabetes", "Hypertension"], ["Penicillin"], ["Metformin 500mg", "Amlodipine 5mg"], "2026-09-12"),
        _p("P-1002", "Divya Raman", 31, "F", "B+", ["Asthma"], [], ["Salbutamol inhaler"], "2026-10-02"),
        _p("P-1003", "Karthik Subbu", 67, "M", "A-", ["Coronary artery disease"], ["Sulfa drugs"], ["Atorvastatin 20mg", "Aspirin 75mg"], "2026-08-21"),
    ],
    "vellore": [
        _p("P-2001", "Meera Iyer", 45, "F", "AB+", ["Hypothyroidism"], [], ["Levothyroxine 75mcg"], "2026-09-30"),
        _p("P-2002", "Rohit Das", 28, "M", "O-", ["Fractured tibia (healed)"], ["Latex"], [], "2026-07-15"),
        _p("P-2003", "Sana Qureshi", 72, "F", "B-", ["Osteoporosis", "Hypertension"], [], ["Alendronate 70mg", "Losartan 50mg"], "2026-10-10"),
    ],
    "bengaluru": [
        _p("P-3001", "Vikram Rao", 59, "M", "A+", ["Atrial fibrillation"], ["Iodine contrast"], ["Warfarin 3mg"], "2026-10-05"),
        _p("P-3002", "Anita Pillai", 38, "F", "O+", ["Migraine"], [], ["Sumatriptan 50mg"], "2026-09-01"),
    ],
    "delhi": [
        _p("P-4001", "Imran Sheikh", 49, "M", "B+", ["COPD"], ["Aspirin"], ["Tiotropium inhaler"], "2026-09-25"),
        _p("P-4002", "Lakshmi Nair", 63, "F", "AB-", ["Chronic kidney disease stage 3"], [], ["Erythropoietin"], "2026-10-18"),
    ],
}
